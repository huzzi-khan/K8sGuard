# K8sGuard vs Kubescape: defensible evaluation protocol

## Key limitation
No Kubescape run is claimed here. These instructions define an experiment to run in the local environment, not fabricated comparison results. A one-day prototype's static analysis coverage is not necessarily comparable to Kubescape's comprehensive posture scanning.

## Matching inputs
Use the same captured Kubernetes manifest data for both tools where supported. Record the Kubescape version, its command line, framework/control identifiers, fixture hash, execution environment, and complete JSON results. Note that some Kubescape controls require live cluster context and cannot be compared fairly against manifest-only input.

## Recommended tests
1. Privileged container: one affected manifest and one nonprivileged control.
2. ServiceAccount with broad RBAC grants: ensure effective subject resolution is evaluated, not just literal roles.
3. Host namespace access: an enabled and disabled fixture.
4. cert-manager ClusterIssuer and external-secrets ClusterSecretStore references: determine whether each tool provides *cross-scope attack-graph relationships*, not merely config inventory.
5. An intentional unresolved CRD reference: measure false assertion of confirmed relationships.

## Reported measurements
- Per scenario: expected behavior, K8sGuard detection, Kubescape detection, evidence path, interpretation, supported/unsupported, and false positives.
- Runtime and peak memory: report measurement method and machine specification; do not assert superiority without data.
- Distinguish feature availability from proven detection correctness.
- Treat "not assessed" separately from false negatives.

## Claim boundaries
MITRE ATT&CK annotations are references, not proof of exploitability. CIS-aligned local rules are NOT version-certified CIS Kubernetes Benchmark controls. K8sGuard hypothetical attack transitions are distinct from observed runtime attacks.
