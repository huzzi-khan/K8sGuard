# Increment 9 — GitHub Actions CI

This package is cumulative, based on Security Engine Increment 8.

## Checks
- **Backend tests:** Python 3.11, bytecode compilation, pytest with downloadable JUnit report.
- **Fixture/API smoke:** no cluster access; checks health, fixture upload, graph, findings, and scan retrieval.
- **Frontend:** Node.js 22, dependency installation with `npm install` (lockfile unavailable; see limitation below), Vite production build and downloadable build artifact.

The jobs run on pull requests and pushes to `main`, `master`, or `develop`; they can also be started manually from GitHub Actions. This is CI only; nothing is deployed and no kubeconfig or live-cluster token is used. The fixture smoke test does not prove a cluster scan works.

## Setup
1. Extract/merge the package into your repository (retain `.git`, private local files, venv).
2. Commit `.github/workflows/ci.yml`, `evaluation/ci_smoke.py`, alongside the source.
3. Push a branch, open a pull request, and view all three checks under **Actions**.
4. Optionally set GitHub branch protection/rulesets so required checks must pass before merging. The exact check names are shown above.

## Local commands
```
cd backend && python -m pip install -r requirements.txt && python -m pytest tests -q
cd ../ && PYTHONPATH=backend python evaluation/ci_smoke.py
cd frontend && npm install && npm run build
```

## Safety
Do not commit `.env`, local tokens, `.kube` or kubeconfig, Python venvs, node_modules, or scan snapshots containing private metadata. CI never calls the live-cluster endpoint.

## Frontend dependency reproducibility limitation
The baseline project contains no `frontend/package-lock.json`. This environment could not reach the npm registry to generate one. CI uses `npm install` rather than the stricter `npm ci`. On your machine, after `npm install`, commit the generated `frontend/package-lock.json`, then change the workflow installation command to `npm ci --no-audit --no-fund` for reproducible installs.
