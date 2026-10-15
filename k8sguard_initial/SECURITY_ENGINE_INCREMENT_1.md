# Security analysis increment 1 — Evidence-linked graph risks

## Implemented
- `backend/app/security_assessment.py`: attaches existing detector evidence to NetworkX node/edge payloads without changing graph connectivity.
- `graph_assessments[]`: stable assessment IDs, finding IDs, target node or relationship, rule/severity, evidence, confidence, MITRE and CIS topic crosswalks, and interpretation.
- `security_state` on nodes and edges: `risk`, `review`, `unassessed`. `unassessed` **does not mean safe**.
- Effective ServiceAccount RBAC findings annotate the binding → role edge; their ServiceAccount and permission scope remain traceable via the assessment payload. Multiple subjects may share the same binding edge.
- Cross-scope Operator references are review-only; crossing a scope by itself is not evidence of exploitability.
- Added explicit effective-RBAC keys to existing MITRE/CIS topic crosswalk. **No version-specific CIS benchmark control identifiers or compliance claims have been invented.**

## Verification
From `backend`, install dependencies and execute `python -m pytest tests -q`.
57 tests pass in the development environment (53 existing + 4 new).

## Intentional limits and required next increment
1. Select exact MITRE ATT&CK release and CIS Kubernetes Benchmark version appropriate to the target Kubernetes distribution. Verify the actual text, control applicability and audit evidence for each candidate rule. The existing topic crosswalk is NOT full benchmark mapping.
2. Move from coarse shared binding → role risk annotations to first-class per-subject effective permission edges or separate permission-grant elements, with correct namespace/resourceNames API semantics.
3. Define per-rule known-good/known-bad/unknown fixtures, validate cross-namespace reference categories, and test false positives/negatives before claiming accurate vulnerability detection.
4. UI should color `risk` red, `review` amber, `unassessed` neutral; clicking a graph element should display all matching `assessment_ids` from `graph_assessments`. Do not treat empty assessments as compliance.
5. Existing `MITRE/*` nodes and `potential_attack_technique` edges are presentation metadata, not traversable Kubernetes attack paths; exclude them from security topology view.

## Unchanged
Existing response fields, local scan token flow, graph layout, previous scanner and React frontend are preserved. No claims are made about live kind integration.
