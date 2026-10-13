# K8sGuard — FYP-1 Module A Starter

**Important:** This is Stage 1, not a complete Module A implementation. It scans offline Kubernetes manifests without changing a cluster. The basic security findings are capability flags; no verified attack path is claimed yet. Modules B/C are planned only.

## Run locally

### Backend (Python 3.11+)

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Backend: http://127.0.0.1:8000/docs

### Frontend (Node.js 20+)

In another terminal:

```bash
cd frontend
npm install
npm run dev
```

Frontend: http://127.0.0.1:5173

Click **Upload YAML**, choose `fixtures/insecure.yaml`, and review the computed results.

## Tests

From project root with backend dependencies installed:

```bash
PYTHONPATH=backend pytest backend/tests -q
```

On Windows PowerShell: `$env:PYTHONPATH="backend"; pytest backend/tests -q`.

## Next development stages

1. Correct effective RBAC resolution, namespace semantics, ClusterRole aggregation, subresources and privilege escalation chains.
2. Full attack-path rules, Pod security context and NetworkPolicy semantics.
3. Operator/CRD cross-scope detection and comparison against Kubescape.
4. Interactive graph rendering and system-level verification.

The in-memory scan store is temporary and resets when backend restarts. Do not expose this starter API to the public Internet.

## Stage 2 update — effective RBAC permissions

The scanner now resolves explicit ServiceAccount subjects through RoleBindings and
ClusterRoleBindings, expands supplied Roles/ClusterRoles, and emits an
`effective_permissions` collection with grant provenance and namespace scope.
It reports unresolved referenced roles and out-of-snapshot ServiceAccounts in
`unresolved_references` rather than silently asserting no access. New effective
access findings include broad wildcard permissions, broad Secrets read, RBAC
mutation and pod exec/attach. These are **capability findings**, not verified
multi-hop attack paths.

**Scope caveats:** Users/Groups, RBAC impersonation, complete ClusterRole
aggregation selectors, API-server authorization plugins, and live-cluster
inventory reconciliation are not fully supported. A RoleBinding to a ClusterRole
is scoped to the binding namespace, not the entire cluster. The scanner does not
apply manifests or modify RBAC. NetworkPolicy and CRD graph expansion remain
future work. Do not present Module A as complete in this iteration.

## Extended Module A (mid-eval iteration)

Use `fixtures/operator_and_paths.yaml` to demonstrate a Deployment's ServiceAccount access through a RoleBinding, a resolved cert-manager ClusterIssuer reference, a pod security warning, and an ingress-deny NetworkPolicy inventory entry.

- `attack_paths` represents **capability/authorization graph paths**, **not proven exploit chains**.
- `operator_references` resolves recognized reference-field names only against objects supplied in the scan. Missing targets remain `unresolved`.
- `network_policies` inventories selected policy direction/rule counts but **does not compute network reachability**.
- Live-cluster discovery and full generalized CRD resolution remain incomplete; do not present this as fully complete Module A.

Run tests: `cd backend && python -m pytest tests -q` (or set `PYTHONPATH=backend` from project root).

For a fresh Git repository, copy **the contents** of this folder into the repository root, not the folder itself. Never overwrite your `.git/` directory or local `.env` files. Commit and push only after reviewing `git status`.


## Stage 4: MITRE ATT&CK / CIS crosswalk

The scan result now provides `mitre_attack` and `cis_kubernetes` entries on findings and candidate capability paths. MITRE references describe *potential enabling conditions*, not observed attacks. Technique-reference graph edges are marked `semantic_only: true` and **must not be traversed as attacker movement edges**.

CIS Kubernetes Benchmark mappings are **topics**, without numbered controls or compliance scores. Before claiming control-level compliance, select a published CIS Kubernetes Benchmark version compatible with the evaluated Kubernetes distribution/version and verify each rule against that source.

Next engineering milestones: selector-aware NetworkPolicy reachability, genuinely multi-hop validated graph rules, generalized CRD discovery, read-only live cluster ingestion, interactive graph visualization, and Kubescape baseline evaluation. Do not describe these as completed.


## Stage 5 patch
- Local CORS origins localhost and 127.0.0.1 (Vite ports 5173/5174) supported. Configure frontend API via `VITE_API_URL` if needed.
- NetworkPolicy LabelSelectors are evaluated against provided **Pod** manifests; the scanner does not assert network reachability or inspect running workloads.
- Run `cd backend && python -m pytest tests -q`, then `cd frontend && npm install && npm run build`.
- Browser console errors can distinguish CORS from backend failures; successful API 200 responses alone do not establish browser access.
