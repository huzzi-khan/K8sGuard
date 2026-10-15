"""Conservative offline ServiceAccount token configuration resolution.

Token mount configuration is evidence about Kubernetes defaults, not evidence
that credentials are usable or an attacker has obtained them.
"""
from __future__ import annotations
from .module_a import namespace, oid, pod_spec, WORKLOADS


def workload_credential_context(docs: list[dict]) -> dict[str, dict]:
    """Return per-workload token configuration, preserving missing-object uncertainty.

    PodSpec automount overrides ServiceAccount automount; if neither is set,
    Kubernetes defaults to token automount enabled. The snapshot can omit a
    ServiceAccount, in which case the ability to obtain a token is unresolved.
    """
    service_accounts = {
        (namespace(o), o['metadata']['name']): o
        for o in docs if o.get('kind') == 'ServiceAccount'
    }
    output = {}
    for obj in docs:
        if obj.get('kind') not in WORKLOADS:
            continue
        spec = pod_spec(obj)
        ns = namespace(obj)
        sa_name = spec.get('serviceAccountName') or 'default'
        sa = service_accounts.get((ns, sa_name))
        pod_value = spec.get('automountServiceAccountToken')
        sa_value = sa.get('automountServiceAccountToken') if sa else None
        if pod_value is False:
            state, source = 'disabled', 'workload_spec'
        elif pod_value is True:
            state, source = 'enabled', 'workload_spec'
        elif sa_value is False:
            state, source = 'disabled', 'service_account'
        elif sa_value is True:
            state, source = 'enabled', 'service_account'
        elif sa is not None:
            state, source = 'enabled_by_kubernetes_default', 'kubernetes_default'
        else:
            state, source = 'unresolved_service_account', 'incomplete_snapshot'
        output[oid(obj)] = {
            'workload': oid(obj), 'service_account': f'ServiceAccount/{ns}/{sa_name}',
            'service_account_in_snapshot': sa is not None,
            'pod_automount': pod_value, 'service_account_automount': sa_value,
            'credential_mount': state, 'decision_source': source,
            'credentials_observed': False,
            'explanation': ('Token automount is disabled by the effective Pod/ServiceAccount setting.'
                            if state == 'disabled' else
                            'Referenced ServiceAccount is absent from the supplied snapshot; credential availability is unresolved.'
                            if state == 'unresolved_service_account' else
                            'Configuration permits projected ServiceAccount token mounting; token possession and API access remain unverified.'),
        }
    return output
