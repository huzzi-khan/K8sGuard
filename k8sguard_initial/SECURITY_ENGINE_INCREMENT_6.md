# Module A — Security Engine Increment 6

## Objective
Improve explicit Kubernetes RBAC special-verb recognition and prevent incorrectly inferred attack transitions from unrelated API groups.

## Implemented
- Classify explicit `escalate` on RBAC `roles` / `clusterroles`, `bind` on RBAC `roles` / `clusterroles`, and `impersonate` on recognized core identity resources (`users`, `groups`, `serviceaccounts`) and supported authentication API resources.
- Add `EFFECTIVE_RBAC_ESCALATE`, `EFFECTIVE_RBAC_BIND`, `EFFECTIVE_RBAC_IMPERSONATE` findings for effective ServiceAccount grants with subject, binding, role, scope, verb, API group and resource evidence.
- Link new findings to binding-to-role graph assessments and permission-grant IDs, with rule-supported risk edge status. These findings describe granted potential capability, **not observed abuse**.
- Produce conditional transitions `POTENTIAL_RBAC_ESCALATE`, `POTENTIAL_RBAC_BIND`, and `POTENTIAL_IDENTITY_IMPERSONATION` only when a supplied workload references the SA, graph edges exist, and token mounting is not explicitly disabled at the PodSpec level.
- Correct transitions for Secret read, RBAC binding mutation and workload creation to respect Kubernetes API groups. This fixes cases where custom API resources with familiar names caused false-positive transitions.
- Preserve existing scanner output shape, frontend contract and existing MITRE/CIS candidate-mapping caveats. New RBAC findings reference MITRE T1078 only as **potential enabling conditions**, not proof a technique occurred.

## Test result
`cd backend && python -m pytest tests -q` — **84 passed**. Eight new tests cover positive/negative permission semantics, evidence links, incorrect API-group avoidance, and opt-out preconditions.

## Important limitations
- Kubernetes authorization can involve identities other than ServiceAccounts, Role and ClusterRole aggregation, admission policy and request-time constraints. The offline engine evaluates only modeled supplied artifacts.
- A right to create or update an RBAC binding is not equivalent to unrestricted privilege escalation. `bind` and `escalate` are separate special verbs with distinct API-server enforcement.
- A potential transition requires assumed attacker workload code execution and usable credentials. Neither is observed by this static scanner.
- Token availability is a conservative approximation; an unset automount field does not confirm that credentials are present. Additional ServiceAccount-level automount, projected token and live authorization checks remain future work.
- CIS Kubernetes Benchmark v2.1.0 exact primary-source control verification remains outstanding. Do not label candidate control IDs as verified v2.1.0 compliance evidence.
- No real-world false-positive rates or comprehensive coverage of MITRE techniques can be inferred from the unit suite.

## Next increment
Permission path severity refinement, binding target and scope constraints, token mounting resolution for ServiceAccount objects, versioned benchmark primary-source audit and a documented adversarial evaluation fixture matrix.
