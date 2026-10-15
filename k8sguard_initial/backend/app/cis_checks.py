"""CIS-aligned evidence checks, NOT a scored CIS Kubernetes Benchmark audit.

Each rule is a local PodSpec assessment with its own stable K8sGuard identifier.
No numbered CIS control is asserted until the selected benchmark's wording,
applicability and audit procedures are separately verified.
"""
from __future__ import annotations
from .module_a import WORKLOADS, oid, pod_spec
from .cis_catalogue import CHECK_TOPICS, candidate, CURRENT_EDITION


def evaluate_static_controls(docs: list[dict]) -> list[dict]:
    checks = []
    for obj in docs:
        if obj['kind'] not in WORKLOADS:
            continue
        spec = pod_spec(obj)
        containers = (spec.get('containers') or []) + (spec.get('initContainers') or [])
        for container in containers:
            sc = container.get('securityContext') or {}
            target = oid(obj)
            name = container.get('name', 'unnamed')
            for rule, field, expected in [('K8SG-CIS-PRIVILEGED', 'privileged', False),
                                          ('K8SG-CIS-ESCALATION', 'allowPrivilegeEscalation', False),
                                          ('K8SG-CIS-ROOTFS', 'readOnlyRootFilesystem', True)]:
                observed = sc.get(field)
                status = 'unknown' if observed is None else ('pass' if observed is expected else 'fail')
                checks.append({'rule_id': rule, 'resource': target, 'container': name,
                               'status': status, 'evidence': {'field': f'securityContext.{field}', 'value': observed},
                               'benchmark': 'CIS Kubernetes Benchmark', 'benchmark_version': None,
                               'cis_control_id': None, 'control_candidate': candidate(CHECK_TOPICS.get(rule)),
                               'assessment_type': 'cis_aligned_local_check_not_compliance'})
        for field in ['hostNetwork', 'hostPID', 'hostIPC']:
            observed = spec.get(field)
            checks.append({'rule_id': f'K8SG-CIS-{field.upper()}', 'resource': oid(obj),
                           'status': 'unknown' if observed is None else ('fail' if observed is True else 'pass'),
                           'evidence': {'field': f'spec.{field}', 'value': observed},
                           'benchmark': 'CIS Kubernetes Benchmark', 'benchmark_version': None,
                           'cis_control_id': None, 'control_candidate': candidate(CHECK_TOPICS.get(f'K8SG-CIS-{field.upper()}')),
                           'assessment_type': 'cis_aligned_local_check_not_compliance'})
    return checks
