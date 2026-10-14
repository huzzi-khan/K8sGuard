# K8sGuard Command Centre milestone

This iteration follows the UI flow in `K8sGuard_Console(1).html`:
- Animated shield/logo intro with Skip intro control (approx. 3.1 s).
- Home / Command centre with real scan metrics and scan-source cards.
- Dark left navigation and light security-operations dashboard.
- Attack Graph page embeds the existing NetworkX-layout-based SVG graph explorer, with real data from FastAPI.
- Module B and C are explicitly labelled future work; no mocked results.
- YAML and token-authenticated localhost live-cluster paths are retained.

## Update
Copy project files into your existing working project, preserving `.git`, the virtual environment, kubeconfig and any uncommitted work. Back up your working project or use a new Git branch before merging.

## Verification
Backend: `cd backend && python -m pip install -r requirements.txt && python -m pytest tests -q` (53 passed in packaging environment).
Frontend: `cd frontend && npm install && npm run build && npm run dev` (npm install timed out in packaging environment; local build unverified).

Run backend in WSL2 with `K8SGUARD_CONTEXT` and `K8SGUARD_LOCAL_SCAN_TOKEN`, bound to `127.0.0.1:8000`; frontend at `http://localhost:5173`.

Note: The live endpoint's previous 503 is NOT resolved by this frontend iteration. It depends on cluster connectivity and collector access. The reference HTML contains simulated runtime/policy values; these have NOT been ported as real data.
