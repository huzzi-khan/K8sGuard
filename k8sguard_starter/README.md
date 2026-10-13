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
