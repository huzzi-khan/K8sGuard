"""Evidence-constrained candidate attacker transitions.

An assumed foothold in a workload is a hypothesis, not an observed compromise.
Only traverses graph edges with real authorization semantics; framework annotation
edges are deliberately excluded. No credentials or exploitation are performed.
"""
from __future__ import annotations

from .module_a import WORKLOADS, namespace, oid, pod_spec


def capability_transitions(docs: list[dict], grants: list[dict], graph) -> list[dict]:
    workloads = {}
    for obj in docs:
        if obj['kind'] not in WORKLOADS:
            continue
        spec = pod_spec(obj)
        sa = f"ServiceAccount/{namespace(obj)}/{spec.get('serviceAccountName') or 'default'}"
        # Either PodSpec opt-out or an explicitly supplied ServiceAccount opt-out
        token = spec.get('automountServiceAccountToken')
        if token is False:
            continue
        workloads.setdefault(sa, []).append((oid(obj), token))

    results, seen = [], set()
    for grant in grants:
        sa = grant['subject']
        verbs, resources = set(grant['verbs']), set(grant['resources'])
        for workload, automount in workloads.get(sa, []):
            steps = [workload, sa, grant['binding'], grant['role']]
            if not all(graph.has_edge(a, b) for a, b in zip(steps, steps[1:])):
                continue
            # resourceNames restrict named-object access, not all-list access.
            read_secrets = bool(resources & {'secrets', '*'}) and bool(verbs & {'get', 'list', 'watch', '*'})
            mutate_binding = bool(resources & {'rolebindings', 'clusterrolebindings', '*'}) and bool(verbs & {'create', 'update', 'patch', '*'})
            deploy_pod = bool(resources & {'pods', 'deployments', '*'}) and bool(verbs & {'create', '*'})
            candidates = []
            if read_secrets:
                candidates.append(('POTENTIAL_SECRET_ACCESS', 'high', 'Kubernetes API read of Secret objects', 'T1078'))
            if mutate_binding:
                candidates.append(('POTENTIAL_RBAC_MUTATION', 'critical', 'Kubernetes RBAC binding modification', 'T1078'))
            if deploy_pod:
                candidates.append(('POTENTIAL_WORKLOAD_CREATION', 'high', 'Workload creation permission', 'T1610'))
            for rule, severity, effect, technique in candidates:
                key = workload, sa, grant['binding'], grant['role'], rule, grant['scope']
                if key in seen:
                    continue
                seen.add(key)
                preconditions = ['Hypothetical attacker code execution in the workload', 'Usable API credentials for the workload ServiceAccount', 'API server reachable and authorization rules applicable']
                if rule == 'POTENTIAL_RBAC_MUTATION':
                    preconditions.append('API admission and RBAC bind/escalate safeguards also permit the requested modification')
                if rule == 'POTENTIAL_SECRET_ACCESS':
                    preconditions.append('Target Secret exists within the grant scope and meets resourceNames restrictions')
                results.append({'id': f'T-{len(results)+1:03}', 'rule': rule, 'severity': severity,
                    'classification': 'conditional_attack_transition', 'nodes': steps,
                    'initial_state': f'Assumed code execution in {workload}', 'possible_effect': effect,
                    'preconditions': preconditions, 'credential_mount': 'explicitly_enabled' if automount is True else 'not_explicitly_disabled',
                    'scope': grant['scope'], 'mitre_technique': technique,
                    'evidence': {'binding': grant['binding'], 'role': grant['role'], 'verbs': grant['verbs'],
                                 'resources': grant['resources'], 'resourceNames': grant['resourceNames']},
                    'confidence': 'conditional; not an observed compromise'})
    return results
