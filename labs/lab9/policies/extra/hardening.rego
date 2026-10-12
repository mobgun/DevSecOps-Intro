package k8s.hardening

# Two checks the shipped k8s.security policy does not make. Run with --all-namespaces,
# so conftest picks this package up alongside k8s.security and compose.security.
#
# The shipped rules only walk spec.template.spec.containers. initContainers run in the
# same pod, with the same service account, network and volumes, and nothing checks them.

# Every container, regular or init, of a Deployment.
all_containers contains c if {
	input.kind == "Deployment"
	c := input.spec.template.spec.containers[_]
}

all_containers contains c if {
	input.kind == "Deployment"
	c := input.spec.template.spec.initContainers[_]
}

# DENY: images must be pinned by digest. The shipped rule only rejects ":latest", so
# ":v20.0.0" passes it, and a tag can be moved to a different image at any time.
# A digest is also what a Cosign signature is bound to (Lab 8).
deny contains msg if {
	c := all_containers[_]
	not contains(c.image, "@sha256:")
	msg := sprintf("container %q image %q must be pinned by digest (name@sha256:...), not by tag", [c.name, c.image])
}

# WARN: initContainers must meet the same baseline the shipped rules demand of
# containers. object.get() turns a missing securityContext into a failure instead of
# an undefined path that silently passes.
warn contains msg if {
	input.kind == "Deployment"
	ic := input.spec.template.spec.initContainers[_]
	sc := object.get(ic, "securityContext", {})
	problems := [p |
		some p in [
			"runAsNonRoot: true",
			"allowPrivilegeEscalation: false",
			"capabilities.drop: [ALL]",
		]
		not init_ok(sc, p)
	]
	count(problems) > 0
	msg := sprintf("initContainer %q is not checked by k8s.security and is missing: %s", [ic.name, concat(", ", problems)])
}

init_ok(sc, "runAsNonRoot: true") if object.get(sc, "runAsNonRoot", false) == true

init_ok(sc, "allowPrivilegeEscalation: false") if object.get(sc, "allowPrivilegeEscalation", true) == false

init_ok(sc, "capabilities.drop: [ALL]") if "ALL" in object.get(sc, ["capabilities", "drop"], [])
