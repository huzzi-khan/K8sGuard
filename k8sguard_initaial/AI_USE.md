# AI Use

2026-10-13: ChatGPT assisted in initial project scaffolding, starter read-only scanner, tests, frontend, and CI. All code must be verified by the project team before evaluation.

2026-10-13: ChatGPT assisted with Stage 2 RBAC resolution module, scanner
integration, and unit tests. Developer must review correctness, reproduce tests,
and verify repository commits before mid-evaluation claims.

- 2026-10-13: ChatGPT assisted with Module A workload checks, recognized Operator/CRD references, limited NetworkPolicy inventory, conservative authorization capability paths, regression tests, and frontend rendering. Human team must review semantic correctness and evaluate against Kubescape. Full network-path and live-cluster features were NOT implemented in this increment.

- 2026-10-13: ChatGPT implemented framework crosswalk, graph semantic technique annotations, UI display, and regression tests. Core attack graph remains human-review-required; validate framework relationships against sources before publication.

2026-10-13 | ChatGPT | Stage 5: local CORS origin support, frontend API error messages and bounded SVG graph visualization, NetworkPolicy LabelSelector coverage for supplied Pod objects, tests, docs | Human verification: frontend npm build requires local installation; backend 20 tests verified in packaging environment.

- 2026-10-13: ChatGPT implemented conditional RBAC attack transitions, CIS-aligned local checks, regression tests, and the Stage 6 UI. Human review and local execution pending.

2026-10-13: AI-assisted addition of Stage 7 NetworkPolicy model, regression tests, optional read-only local cluster collector, and documentation. Human review and local cluster testing pending. The policy model intentionally does not claim actual CNI connectivity.

## 2026-10-13 Stage 8
- Assistant implemented frontend interactive attack graph from Stage 7 scanner JSON in `frontend/src/AttackGraph.jsx`, `frontend/src/attack-graph.scss`, updated `frontend/src/main.jsx`.
- Node/edge selection, search, kind filter, path highlighting, pan/zoom, evidence inspector; no fabricated data.
- `python -m pytest tests -q`: 30 passed. Frontend `npm install` timed out and frontend build is **not verified** in this environment; verify locally before evaluation.

- 2026-10-13, ChatGPT: added HTTP API integration and CORS tests, offline fixture evidence exporter, Kubescape comparison protocol and mid-evaluation evidence checklist. Scanner algorithms unchanged in this increment. User should verify frontend build and any live-cluster claims locally.
