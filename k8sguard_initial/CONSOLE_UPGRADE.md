# Console-style graph upgrade

Reference: user Library `K8sGuard_Console.html` (visual language only). No static mock security findings were imported.

- Real `NetworkX` nodes and edges remain authoritative via `scanner.analyze`.
- `backend/app/graph_layout.py` returns deterministic display positions as `graph_layout`, not extra risk evidence.
- Frontend `AttackGraph.jsx` places real scan nodes using the NetworkX geometry; falls back to a simple grid for prior scan JSON lacking layout.
- Updated console-style light canvas, dark navigation rail, graph controls, inspector, legend and KPI cards.
- No changes to live scan authentication, collector, or YAML upload endpoints.

Run backend: `python -m pytest tests -q`
Run frontend: `npm install && npm run build && npm run dev`

NOTE: NetworkX runs on Python backend; the web client renders the resulting topology as interactive SVG. Rendering *is not* done by NetworkX in a browser.
