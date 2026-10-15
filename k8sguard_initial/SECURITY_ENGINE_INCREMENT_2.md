# Security Engine Increment 2 — upstream CIS policy crosswalk

## Source verification (2026-10-15)

- CIS official upstream Kubernetes benchmark listing reports **2.1.0** as the most recent edition: https://www.cisecurity.org/benchmark/kubernetes
- CIS official June 2026 release post confirms **2.0.1** supported Kubernetes 1.34/1.35: https://www.cisecurity.org/insights/blog/cis-benchmarks-june-2026-update
- Public implementation reference with numbered policy recommendations: https://github.com/aquasecurity/kube-bench/discussions/1778
- Numbered recommendations are **candidate mappings**, not independently verified against the primary **2.1.0** document. `benchmark_version: null` is intentional. Obtain official 2.1.0 PDF, independently verify control IDs, text, manual/automated status, applicability and audit procedure before promoting them to edition-verified controls.

## Changes

- New `backend/app/cis_catalogue.py`: upstream version metadata, candidate control numbers, provenance, status.
- `frameworks.py`: findings and graph assessments inherit candidate CIS references with explicit verification status.
- `cis_checks.py`: local PodSpec check output carries `control_candidate` without asserting benchmark compliance.
- Three regression tests, previous test adjusted to check absence of fabricated **edition-verified** control IDs.

## Scope and limitations

- Static analysis only; does not inspect admission policy enforcement, node configuration, CNI implementation or control-plane flags.
- A privileged container configuration is not equivalent to verifying an admission-control CIS recommendation. `fail` means the **local K8sGuard predicate** failed, not the full benchmark audit.
- Rule mappings do not imply exploitation. Effective RBAC permissions must be evaluated in context.
- MITRE mappings are unchanged from Increment 1 and remain partial.
- Frontend has not changed; source format remains backward-compatible.
- Do not publish this as an official CIS compliance report.

## Reproduce

```
cd backend
python -m pip install -r requirements.txt
python -m pytest tests -q
```

Expected: **60 passed** (verified in the supplied environment).

## Next increment

1. Obtain and check primary upstream CIS 2.1.0 PDF (specific edition, not benchmark landing page).
2. Verify control-number/title/audit/assessment correspondence; promote only those truly supported.
3. Separate config indicators, admission policy enforcement, and full benchmark audits.
4. Add exact evidence on individual authorization grants and edge investigation UI.
