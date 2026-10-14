# K8sGuard Module A — Backend audit (2026-10-14)

## Verified locally
- `python -m pytest tests -q`: 51 passed (37 preexisting + 14 new collector metadata tests).
- Fixture `insecure.yaml`: 4 documents, 7 nodes, 7 edges, 9 findings, 3 capability paths.
- Fixture `operator_and_paths.yaml`: 7 documents, 10 nodes, 6 edges, 5 findings, 1 capability path.
- NetworkX DiGraph creates backend graph; the frontend is a separate visualization layer.

## Fixed
- Fallback Kubernetes API group/versions for batch/v1 Jobs/CronJobs, rbac.authorization.k8s.io/v1 roles/bindings and networking.k8s.io/v1 NetworkPolicy.
- Collector now preserves existing kind/apiVersion and does not modify the source item dictionary.

## Not verified; do not claim passed
- Real kind API connection and inventory consistency from this isolated test environment (user reports live frontend graph successfully loads on their machine).
- Arbitrary custom resources/CRD discovery, Kubernetes list pagination, security detection recall/precision, production scalability.
- Live network connectivity: network policy reasoning is static approximation only.
- Cross-namespace and edge-case RBAC semantics beyond unit fixtures.
- Actual comparative benchmark against Kubescape.

## Recommended next tests
1. Capture `kubectl get` inventory and compare with live collected snapshot.
2. Deploy a controlled isolated namespace with known-safe and known-insecure RBAC / workload / NetworkPolicy fixtures.
3. Assert exact expected findings, permissions, edges and attack paths; write regression tests for any mismatch.
4. Test partial RBAC read access, collection errors, malformed YAML, duplicate resource identities and pagination.
5. Only then move to frontend UX and graph presentation.
