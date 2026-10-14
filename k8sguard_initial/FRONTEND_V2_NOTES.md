# Console V2 — NetworkX graph frontend refinement

The existing FastAPI scanner, attack-path engine, live collector, and YAML upload flow are preserved.

## Updates
- Resource-type shapes: workload rectangles, rounded identity nodes, square-corner RBAC resources; consistent colored node accents.
- Namespace-level translucent regions drawn around real resource nodes (visual groupings only).
- Optional directed relationship labels, semantic MITRE/CIS edges, and edge evidence.
- Search, namespace/resource-type filters, path highlighting, fit/zoom/pan, and an expanded resource inspector.
- Inspector includes connected resources, associated findings where matching evidence is available, raw node and edge metadata, and conditional-path prerequisites.
- Legend distinguishing workloads, identities, RBAC, secrets, NetworkPolicy, and selected path.
- Uses backend-provided NetworkX graph layout; falls back to deterministic grid coordinates if no positions exist.
- Added NumPy requirement because NetworkX spring_layout requires it (user's WSL2 test found this missing).

## Verification
- Backend: 53/53 pytest tests passed in the provided environment.
- Frontend: production build NOT verified here. `npm install` failed due to registry DNS resolution (EAI_AGAIN). Run `npm install && npm run build` locally.
- Live WSL2 kind scanning NOT re-tested in this environment.

## Install
Copy this project into your existing repository (preserve .git and local venv). On WSL2:

```
cd backend
python -m pip install -r requirements.txt
python -m pytest tests -q
cd ../frontend
npm install
npm run build
npm run dev
```

Keep both servers on localhost and never commit a live scan token.
