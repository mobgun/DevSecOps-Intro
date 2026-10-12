# Lab 9 — Runtime Detection and Policy as Code

**Environment**
- Host: Windows 11, Docker Desktop 29.7.2 on Hyper-V (no WSL), Git Bash.
- Falco: `falcosecurity/falco:0.43.1`, using the **modern BPF probe** (`Opening 'syscall' source with modern BPF probe`).
- Conftest: `conftest 0.69.0` (OPA 1.19.0).

**Where Falco ran.** The lab warns that a desktop Docker VM "does not expose the host kernel". That holds here as well, but it does not matter. Falco attaches to the kernel of the Docker Desktop VM (`7.0.12-linuxkit`, with `/sys/kernel/btf/vmlinux` present), and every container runs on that same kernel, so Falco sees all of them. I ran the lab's `docker run` unchanged, apart from `MSYS_NO_PATHCONV=1` and an absolute `D:/…` path for the rules mount, so that Git Bash would not rewrite `/proc` and the other Linux paths. At startup Falco printed the expected `failure while attaching TOCTOU mitigation program` lines for `connect`, `creat`, `open`, `openat` and `openat2`. Detection still worked, as the lab says it should.

## Task 1

### 9.2 The two built-in rules

```bash
docker exec -t lab9-target sh -lc 'echo hello-from-shell'
docker exec lab9-target sh -c 'cat /etc/shadow'
docker logs falco 2>&1 | grep -o '"rule":"[^"]*"' | sort | uniq -c
#   1 "rule":"Read sensitive file untrusted"
#   1 "rule":"Terminal shell in container"
```

**`Terminal shell in container`** (Notice; tags `T1059`, `mitre_execution`). The trigger was `docker exec -t … sh -lc`: a shell (`execve` of `sh`) started with a terminal attached. Without `-t` the rule does not fire, because it keys on the terminal (`proc.tty`).

```text
Notice A shell was spawned in a container with an attached terminal | evt_type=execve user=root user_uid=0 user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=containerd-shim command=sh -lc echo hello-from-shell terminal=34816 exe_flags=EXE_WRITABLE|EXE_LOWER_LAYER container_id=3526e8a96a12 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20
```

**`Read sensitive file untrusted`** (Warning; tags `T1555`, `mitre_credential_access`). The trigger was `cat /etc/shadow`: a program not on the trusted list opened the password-hash file for reading.

```text
Warning Sensitive file opened for reading by non-trusted program | file=/etc/shadow gparent=initd evt_type=open user=root user_uid=0 user_loginuid=-1 process=cat proc_exepath=/bin/busybox parent=containerd-shim command=cat /etc/shadow terminal=0 container_id=3526e8a96a12 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20
```

### 9.3 A rule the defaults do not have

The shipped `falco_rules.yaml` has no rule for writes under `/tmp`. The rule is built from two shipped macros:
- `open_write`: `evt.type in (open,openat,openat2) and evt.is_open_write=true and fd.typechar='f' and fd.num>=0`;
- `container`: `container.id != host`.

[`labs/lab9/falco/rules/custom-rules.yaml`](../labs/lab9/falco/rules/custom-rules.yaml):

```yaml
- rule: Write below tmp in container
  desc: >
    A process inside a container (not on the host) opened a regular file under
    /tmp for writing. Signals runtime drift from the image: staged payloads,
    downloaded tools or scripts written before execution.
  condition: >
    open_write
    and container
    and fd.name startswith /tmp/
  output: >
    File opened for writing under /tmp in a container
    (container=%container.name image=%container.image.repository:%container.image.tag
    user=%user.name uid=%user.uid file=%fd.name command=%proc.cmdline
    parent=%proc.pname container_id=%container.id)
  priority: WARNING
  tags: [container, drift]
```

```bash
docker kill --signal=SIGHUP falco && sleep 5
docker exec --user 0 lab9-target sh -lc 'echo test > /tmp/my-write.txt'
docker logs falco 2>&1 | grep -c '"rule":"Write below tmp in container"'   # -> 1
```

```json
{
  "hostname": "30f4b8482ede",
  "priority": "Warning",
  "rule": "Write below tmp in container",
  "source": "syscall",
  "tags": ["container", "drift"],
  "time": "2026-10-12T05:37:14.240962380Z",
  "output": "2026-10-12T05:37:14.240962380+0000: Warning File opened for writing under /tmp in a container (container=lab9-target image=alpine:3.20 user=root uid=0 file=/tmp/my-write.txt command=sh -lc echo test > /tmp/my-write.txt parent=containerd-shim container_id=3526e8a96a12) container_id=3526e8a96a12 container_name=lab9-target container_image_repository=alpine container_image_tag=3.20 k8s_pod_name=<NA> k8s_ns_name=<NA>",
  "output_fields": {
    "container.id": "3526e8a96a12",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "evt.time.iso8601": 1791783434240962380,
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo test > /tmp/my-write.txt",
    "proc.pname": "containerd-shim",
    "user.name": "root",
    "user.uid": 0
  }
}
```

**Negative check.** Writing `/root/not-tmp.txt` and `/var/tmp/also-not.txt` in the same container left the count at 1. The rule matches the path prefix it names and nothing else.

**An incident field that is not in the message: `hostname`.** The human-readable line names the container but never the machine that saw it. In a fleet, where Falco runs as a DaemonSet, `hostname` is the node, and that is what you need to isolate or cordon the node and pull its other logs. Here it holds the Falco container's own ID (`30f4b8482ede`), because Falco runs as a plain container without `--hostname`. That is a deployment detail to fix before an incident, not during one. A close second is `tags` on the built-in alerts: the MITRE technique ID (`T1059`, `T1555`) maps the alert straight onto an ATT&CK-based playbook and never appears in the message text.

**False positives and tuning.** The rule fires on every `/tmp` write in every container. Any JVM does that at startup, because it writes `/tmp/hsperfdata_<user>/<pid>`. So do Python's `tempfile`, `pip` and many upload handlers. A Java service would therefore alert on every start, and the alert stops meaning anything. I would keep the detection and cut the noise in this order:
1. Add per-workload exceptions keyed on image **and** path. Falco `exceptions` with `container.image.repository` and `fd.name startswith /tmp/hsperfdata_` exclude the known writer without blinding the rule for everyone else.
2. Where the image allows it, mount `/tmp` as an `emptyDir` or `tmpfs` with `noexec` (Lab 7's read-only root does this). Then a write is harmless, and the signal worth keeping is *execution* of something written after start. The shipped `Drop and execute new binary in container` rule (`proc.is_exe_upper_layer`) covers that.
3. Widen the path list rather than narrow it. Real droppers also use `/var/tmp` and `/dev/shm`, and my negative check shows the rule misses `/var/tmp` today.

## Task 2

### 9.4 What ships

```bash
conftest test labs/lab9/manifests/k8s/juice-hardened.yaml   --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/k8s/juice-unhardened.yaml --policy labs/lab9/policies --all-namespaces
conftest test labs/lab9/manifests/compose/juice-compose.yml --policy labs/lab9/policies --all-namespaces
```

| Manifest | Tests | Passed | Warnings | Failures |
|---|---|---|---|---|
| `k8s/juice-hardened.yaml` | 30 | 30 | 0 | 0 |
| `k8s/juice-unhardened.yaml` | 30 | 20 | 2 | **8** |
| `compose/juice-compose.yml` | 15 | 15 | 0 | 0 |

Unhardened: 8 FAIL (`:latest`, `runAsNonRoot`, `allowPrivilegeEscalation`, `readOnlyRootFilesystem`, four `resources.*`) and 2 WARN (`livenessProbe`, `readinessProbe`).

**Two failures mapped to their rules in `k8s-security.rego`:**
- `container "juice" uses disallowed :latest tag` comes from **lines 10–15**: `endswith(c.image, ":latest")` on `bkimminich/juice-shop:latest`.
- `container "juice" must set allowPrivilegeEscalation: false` comes from **lines 25–30**: `not c.securityContext.allowPrivilegeEscalation == false`. The manifest has no `securityContext`, so the comparison is not true and the negation fires.

**A shipped rule that never fires.** The unhardened manifest has no `securityContext` at all, yet `must drop ALL capabilities` (**lines 39–44**) is *not* among its failures. I tested it in isolation:

| Container's `securityContext` | Rule fires? |
|---|---|
| none at all | **no** |
| present, without `capabilities` | **no** |
| `capabilities.drop: [NET_RAW]` | yes |

`not has_value(c.securityContext.capabilities.drop, "ALL")` only fires when a `drop` list exists and lacks `ALL`. When the path is undefined, the function call is undefined and the rule does not fire, so the worst manifest passes this check. The fix is `object.get(c, ["securityContext", "capabilities", "drop"], [])`. The extra policy below uses that pattern.

**What the test counts mean.** With `--all-namespaces`, every rule in every package runs against every YAML document:
- The Kubernetes files have 2 documents (the Deployment and the Service) and the policies have 15 rules (11 in `k8s.security`, 4 in `compose.security`), so 2 × 15 = 30.
- The Compose file has 1 document, so 15.

Most of those "passes" are vacuous. On the Compose file, `--namespace k8s.security` reports `11 tests, 11 passed`, all of them rules gated on `input.kind == "Deployment"` that cannot apply.

**Why Compose and Kubernetes need separate rules.** The same requirement, "don't run as root, drop all capabilities, read-only root", is spelled differently in each schema:

| Requirement | Compose | Kubernetes |
|---|---|---|
| Non-root user | `user:` | `securityContext.runAsNonRoot` |
| Capabilities | `cap_drop:` | `securityContext.capabilities.drop` |
| Read-only root | `read_only:` | `securityContext.readOnlyRootFilesystem` |

Rego rules match on document structure, not intent, so each format needs its own rule.

**What the Compose file passing tells me.** Only that it meets the **4** Compose rules that actually apply to it: explicit `user: "10001:10001"`, `read_only: true`, `cap_drop: ["ALL"]` and `no-new-privileges:true`. It does not mean it passed 15 checks. A policy that has never been seen failing on its target format has not shown that it can fail. The capabilities bug above is exactly that kind of rule.

### 9.5 Extending the policy

[`labs/lab9/policies/extra/hardening.rego`](../labs/lab9/policies/extra/hardening.rego) is `package k8s.hardening`, picked up by `--all-namespaces`. The shipped rules only walk `spec.template.spec.containers`, so both of mine also cover **`initContainers`**, which run in the same pod with the same service account, network and volumes, and which nothing checks today.

```rego
all_containers contains c if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
}

all_containers contains c if {
	input.kind == "Deployment"
	c := input.spec.template.spec.initContainers[_]
}

# DENY: images must be pinned by digest. The shipped rule only rejects ":latest";
# ":v20.0.0" passes it, and a tag can be moved. A digest is what Cosign signs (Lab 8).
deny contains msg if {
	c := all_containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q image %q must be pinned by digest (name@sha256:...), not by tag", [c.name, c.image])
}

# WARN: initContainers must meet the baseline the shipped rules demand of containers.
warn contains msg if {
	input.kind == "Deployment"
	ic := input.spec.template.spec.initContainers[_]
	sc := object.get(ic, "securityContext", {})
	problems := [p |
		some p in ["runAsNonRoot: true", "allowPrivilegeEscalation: false", "capabilities.drop: [ALL]"]
		not init_ok(sc, p)
	]
	count(problems) > 0
	msg := sprintf("initContainer %q is not checked by k8s.security and is missing: %s", [ic.name, concat(", ", problems)])
}

init_ok(sc, "runAsNonRoot: true") if object.get(sc, "runAsNonRoot", false) == true
init_ok(sc, "allowPrivilegeEscalation: false") if object.get(sc, "allowPrivilegeEscalation", true) == false
init_ok(sc, "capabilities.drop: [ALL]") if "ALL" in object.get(sc, ["capabilities", "drop"], [])
```

The manifest I wrote to violate it is [`labs/lab9/manifests/k8s/juice-violates-extra.yaml`](../labs/lab9/manifests/k8s/juice-violates-extra.yaml), committed rather than left in `/tmp`. Its main container is fully hardened, but it is pinned by tag (`bkimminich/juice-shop:v20.0.0`), and it adds an initContainer `fetch-config` (`alpine:3.20`) with no `securityContext`.

```text
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures, 0 exceptions

$ conftest test labs/lab9/manifests/k8s/juice-violates-extra.yaml --policy labs/lab9/policies --all-namespaces
WARN - … - k8s.hardening - initContainer "fetch-config" is not checked by k8s.security and is missing: runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities.drop: [ALL]
FAIL - … - k8s.hardening - container "fetch-config" image "alpine:3.20" must be pinned by digest (name@sha256:...), not by tag
FAIL - … - k8s.hardening - container "juice" image "bkimminich/juice-shop:v20.0.0" must be pinned by digest (name@sha256:...), not by tag
18 tests, 15 passed, 1 warning, 2 failures, 0 exceptions

$ conftest test labs/lab9/manifests/k8s/juice-violates-extra.yaml --policy labs/lab9/policies --namespace k8s.security
11 tests, 11 passed, 0 warnings, 0 failures, 0 exceptions        # the shipped policy alone lets it through
```

With the extra package loaded:
- **hardened:** 30 → **34** tests (2 rules × 2 documents);
- **unhardened:** 8 → **9** failures (its `:latest` also fails the digest rule);
- **Compose:** 15 → 17 tests, all vacuous for my rules.

**CI or runtime: which one I would keep.** For digest pinning I would keep the **Conftest** rule. It is a property of the manifest, fully decidable before deploy, and the deploy is exactly where it has to hold. A digest-pinned deploy is what makes Lab 8's signatures enforceable, and catching it at runtime would mean the unpinned pod is already running.

What a runtime rule still buys is coverage of everything that never passes through this CI: a `kubectl apply` or `kubectl set image` from someone's laptop, a Helm chart rendered elsewhere, a mutating webhook that rewrites the image. A Falco rule on new containers whose image has no digest catches drift away from the policy, not just violations of it. The same split applies to the initContainer warn: CI stops it in review, and Falco would see what such a container actually does when it runs.

## Bonus — Catch a cryptominer

```yaml
- list: miner_pool_ports
  items: [3333, 4444, 5555, 7777, 14444]

- macro: connect_to_pool_port
  condition: >
    (fd.sport in (miner_pool_ports)
     or evt.arg.addr endswith ":3333"
     or evt.arg.addr endswith ":4444"
     or evt.arg.addr endswith ":5555"
     or evt.arg.addr endswith ":7777"
     or evt.arg.addr endswith ":14444")

- list: miner_process_names
  items: [xmrig, xmr-stak, minerd, cpuminer, cgminer, bfgminer, ethminer, nbminer, lolminer, ccminer, t-rex]

- list: raw_socket_tools
  items: [nc, ncat, netcat, socat]

- rule: Possible cryptominer pool connection
  desc: >
    A process in a container attempted a TCP/UDP connection to a typical mining-pool
    port, and the process is a known miner binary, a raw socket tool, or uses a
    stratum URL. Either signal alone is noisy; together they are worth waking up for.
  condition: >
    evt.type = connect
    and container
    and (fd.typechar = 4 or fd.typechar = 6)
    and connect_to_pool_port
    and (proc.name in (miner_process_names)
         or proc.name in (raw_socket_tools)
         or proc.cmdline contains "stratum+tcp")
  output: >
    Possible cryptominer connecting to a pool port
    (container=%container.name container_id=%container.id image=%container.image.repository:%container.image.tag
    process=%proc.name exe=%proc.exepath command=%proc.cmdline user=%user.name
    destination=%evt.arg.addr connection=%fd.name result=%evt.res)
  priority: CRITICAL
  tags: [container, network, mitre_command_and_control, mitre_impact, T1496]
```

```text
$ docker exec lab9-target sh -c 'nc -w 2 127.0.0.1 3333' || true
$ docker logs falco 2>&1 | grep -c '"priority":"Critical"'
1
```
```text
Critical Possible cryptominer connecting to a pool port (container=lab9-target container_id=3526e8a96a12 image=alpine:3.20 process=nc exe=/bin/busybox command=nc -w 2 127.0.0.1 3333 user=root destination=127.0.0.1:3333 connection=0.0.0.0:0 result=ECONNREFUSED)
tags: ["T1496","container","mitre_command_and_control","mitre_impact","network"]
```

There were two negative checks, and neither added an alert:
- `wget` to `127.0.0.1:3333`: the port matches, the process does not;
- `nc` to `127.0.0.1:3334`: the process matches, the port does not.

So both signals are required.

**Two departures from the lab's hints, both found by testing:**
1. **`fd.sport` is empty for a refused connect.** My first version used the hint's `fd.sport in (…)` and fired 0 times. A temporary debug rule showed why: for the failed `connect`, the event carries `fd.name=0.0.0.0:0`, `fd.sport=<NA>` and `tuple=NULL`, because the socket never gets a connected 4-tuple. Falco 0.43 also drops enter events, and those used to carry the address. The destination survives only in the exit event's own argument, `evt.arg.addr=127.0.0.1:3333`, so the macro checks both: `fd.sport` for established connections and `evt.arg.addr` for refused or in-progress ones.
2. **`evt.dir = <` is deprecated.** Falco 0.43 loaded the hint's condition with `LOAD_DEPRECATED_ITEM … 'evt.dir = <' always evaluates to true`, so I removed it.

I also did not reuse the shipped `outbound` macro. It excludes `127.0.0.0/8` and requires `evt.rawres >= 0 or EINPROGRESS`, so it would drop exactly the refused loopback test.

**Why a refused connection is enough.** Falco watches the `connect()` **system call** in the kernel, not packets on the wire. The process has already decided where to connect and asked the kernel to do it, so the event and its destination exist whether the peer answers, refuses or is blocked by a firewall. The intent is the signal; a successful pool session is not needed. This also means Falco sits below the network: a NetworkPolicy or egress firewall that blocks the miner does not hide the attempt from Falco, which is exactly what you want when the miner is already inside.

**Evasion.**
- **The port is free to change.** Pools listen wherever the operator wants, including 443 and 80, and this attacker controls the pool. Detection on the port alone falls to a one-line config change.
- **The process name is almost as cheap.** Renaming `xmrig` to `kworker` defeats `proc.name in (…)`, and `nc` is only on the list as a stand-in for testing.
- **The expensive parts are behaviour.** A miner must keep a long-lived outbound connection to a host the workload has no business talking to, speak the stratum protocol (`mining.subscribe`, `mining.authorize` in cleartext JSON-RPC), and burn CPU.

To catch the evasion I would add:
- **An egress allowlist:** a NetworkPolicy plus a Falco rule for any outbound connection from a workload to a destination outside its known set. That survives every port change.
- **Drift detection on the binary:** `proc.is_exe_upper_layer`, meaning a binary that was not in the image was executed. That survives renaming.
- **CPU-saturation alerts** from the metrics side.

Together these make the attacker change behaviour rather than configuration.

## Clean-up

`docker rm -f falco lab9-target` after the run. Falco's JSON alerts were saved under `labs/lab9/falco/logs/`, which is gitignored and not committed.
