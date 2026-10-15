# K8sGuard Security Engine — Increment 3

Added deterministic individual permission-grant evidence records from resolved RBAC: subject, binding, role, scope, API group, resource, verb, resource-name restrictions, risk indicators, and a stable permission grant ID. Existing `graph_assessments` can now reference supporting `permission_grant_ids`. These records are *not new topology edges*; they preserve the existing graph API and avoid rendering hundreds of duplicate authorization edges.

**Limitations:** rule heuristics are static and incomplete; API-group/resource semantics, `resourceNames` on list/watch, RoleRef validity in live discovery, aggregated ClusterRoles and RBAC escalation preconditions need further formal verification. Unassessed does not mean secure. MITRE/CIS mappings remain candidate crosswalks, not certified audits. UI not changed.

Run: `cd backend && python -m pip install -r requirements.txt && python -m pytest tests -q`.
