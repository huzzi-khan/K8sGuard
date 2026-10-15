"""Upstream CIS Kubernetes policy reference catalogue.

CIS lists upstream v2.1.0 as current (October 2026). Exact control numbering
below is supported by published kube-bench policy references, but MUST be
cross-checked against the selected primary v2.1.0 PDF before being called a
verified v2.1.0 control. A candidate mapping is not a benchmark audit.
"""
BENCHMARK = 'CIS Kubernetes Benchmark'
CURRENT_EDITION = '2.1.0'
SOURCE = 'https://www.cisecurity.org/benchmark/kubernetes'
SECONDARY = 'https://github.com/aquasecurity/kube-bench/discussions/1778'
# These identifiers are verified against published upstream policy mappings,
# NOT independently against the v2.1.0 primary benchmark text.
POLICY_CANDIDATES = {
    'secrets_access': ('5.1.2', 'Minimize access to secrets'),
    'rbac_wildcards': ('5.1.3', 'Minimize wildcard use in Roles and ClusterRoles'),
    'create_pods': ('5.1.4', 'Minimize access to create pods'),
    'default_sa': ('5.1.5', 'Ensure that default service accounts are not actively used'),
    'token_mount': ('5.1.6', 'Ensure that Service Account Tokens are only mounted where necessary'),
    'privileged': ('5.2.1', 'Minimize the admission of privileged containers'),
    'host_pid': ('5.2.2', 'Minimize the admission of containers sharing the host process ID namespace'),
    'host_ipc': ('5.2.3', 'Minimize the admission of containers sharing the host IPC namespace'),
    'host_network': ('5.2.4', 'Minimize the admission of containers sharing the host network namespace'),
    'privilege_escalation': ('5.2.5', 'Minimize the admission of containers with allowPrivilegeEscalation'),
}
RULE_TOPICS = {
    'EFFECTIVE_SECRET_READ': 'secrets_access', 'RBAC_SECRET_READ': 'secrets_access',
    'SECRET_READ_CAPABILITY': 'secrets_access',
    'RBAC_WILDCARD': 'rbac_wildcards', 'EFFECTIVE_RBAC_WILDCARD': 'rbac_wildcards',
    'PRIVILEGED_CONTAINER': 'privileged',
    'POD_HOSTPID': 'host_pid', 'POD_HOSTIPC': 'host_ipc',
    'POD_HOSTNETWORK': 'host_network',
    'PRIVILEGE_ESCALATION_ALLOWED': 'privilege_escalation',
    'POD_TOKEN_AUTOMOUNT': 'token_mount',
}
CHECK_TOPICS = {
    'K8SG-CIS-PRIVILEGED': 'privileged', 'K8SG-CIS-ESCALATION': 'privilege_escalation',
    'K8SG-CIS-HOSTPID': 'host_pid', 'K8SG-CIS-HOSTIPC': 'host_ipc',
    'K8SG-CIS-HOSTNETWORK': 'host_network',
}

def candidate(topic):
    if topic not in POLICY_CANDIDATES:
        return None
    control_id, title = POLICY_CANDIDATES[topic]
    return {'benchmark': BENCHMARK, 'current_upstream_edition': CURRENT_EDITION,
            'control_id': control_id, 'title': title,
            'benchmark_version': None,
            'mapping_status': 'candidate_number_verified_in_secondary_reference_pending_v2.1_primary_review',
            'assessment_type': 'local_static_indicator_not_cis_compliance',
            'sources': [SOURCE, SECONDARY]}
