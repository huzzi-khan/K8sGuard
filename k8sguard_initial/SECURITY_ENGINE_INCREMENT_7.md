# Module A — Increment 7: Credential Evidence and Path Explainability

This cumulative package contains all prior increments. **Apply this package once**, not incremental patches 1–6 in sequence.

## Changes
- `credential_evidence.py`: conservative PodSpec/ServiceAccount automount precedence.
- `attack_engine.py`: suppression of hypothetical token-based transitions for effective `automountServiceAccountToken: false` (including ServiceAccount-level false), retention of unresolved snapshot uncertainty and machine-readable explainability per transition.
- `test_increment7_credential_evidence.py`: secure/insecure/ambiguous regression matrix.

## Important limitations
- A token mount setting alone does not establish possession of credentials, API reachability, or exploitability.
- Other credential sources (explicit Secret mounts, kubeconfig, cloud identity, injected tokens) are not modeled by this gate.
- A missing ServiceAccount in an offline snapshot is **unresolved**, not a verified default or a verified mounted token.
- Existing `attack_paths` capability summaries are distinct from more strictly gated `attack_transitions`; path summary rendering should preserve this distinction.
- CIS 2.1.0 primary-source audit/control verification remains outstanding; candidate associations are **not official CIS pass/fail reports**.

## End-to-end frontend explainability contract
Each `attack_transitions[]` record has `credential_evidence`, `explainability.configuration_fact`, `explainability.hypothesis`, `explainability.unknowns`, `preconditions`, `evidence`, `scope`, and `mitre_technique`. The UI should display these separately under **Verified configuration**, **Conditional attack hypothesis**, **Unknowns**, and **Framework context**. Existing `graph_assessments[]` provide click targets, permission IDs, and associated finding evidence. This increment does not claim frontend support for these new transition fields.

## Validation
`cd backend && python -m pytest tests -q`
