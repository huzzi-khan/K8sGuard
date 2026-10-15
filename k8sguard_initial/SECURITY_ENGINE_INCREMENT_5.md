# Module A — Security Engine Increment 5

## Scope

Rule-semantics accuracy hardening for upstream Kubernetes RBAC. Reuses Increment 4 UI and the same API fields.

### Corrections
- Core Secrets detection requires API group `""` or wildcard `"*"`, not merely the resource string `secrets`.
- RBAC mutation requires API group `rbac.authorization.k8s.io` or wildcard group.
- Pod exec/attach requires core API group or wildcard group.
- Named `resourceNames` read is distinguished from unrestricted Secret reading.
- Original Role-level checks now use the same rule semantics as effective ServiceAccount grants, preventing inconsistent node classifications.
- Wildcard grants remain potential capabilities; results do not imply observed use or exploitation.

### Tests
11 additional secure/insecure/ambiguous regression cases; `76 passed` locally.

### Known limitations
- Version-specific CIS Kubernetes v2.1 control numbers are still candidate mappings pending primary-text verification.
- This increment does not add Kubernetes SubjectAccessReview resolution or audit actual runtime permissions.
- Permissions with nonResourceURLs, wildcard expansion, aggregation with selector expressions, admission webhooks and escalation preconditions remain limited; unassessed does not imply secure.
- MITRE links are potential enabling conditions, not evidence of technique execution.
- Live kind collection / frontend browser testing was not performed.
