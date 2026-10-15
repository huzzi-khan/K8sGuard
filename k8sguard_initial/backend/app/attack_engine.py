"""Evidence-constrained candidate attacker transitions.

An assumed foothold in a workload is a hypothesis, not an observed compromise.
Only traverses graph edges with real authorization semantics; framework annotation
edges are deliberately excluded. No credentials or exploitation are performed.
"""
from __future__ import annotations

from .credential_evidence import workload_credential_context
from .rbac_rule_semantics import indicators_for_rule, covers_group


def covers_group_any(groups: set[str], expected: str) -> bool:
    return any(covers_group(group, expected) for group in groups)


def capability_transitions(docs: list[dict], grants: list[dict], graph) -> list[dict]:
    credential_context = workload_credential_context(docs)
    workloads = {}
    for workload, credential in credential_context.items():
        if credential['credential_mount'] == 'disabled':
            continue
        workloads.setdefault(credential['service_account'], []).append((workload, credential))

    results, seen = [], set()
    for grant in grants:
        sa = grant['subject']
        verbs, resources = set(grant['verbs']), set(grant['resources'])
        indicators = indicators_for_rule(grant)
        groups = set(grant.get('apiGroups', ['']))
        for workload, credential in workloads.get(sa, []):
            steps = [workload, sa, grant['binding'], grant['role']]
            if not all(graph.has_edge(a, b) for a, b in zip(steps, steps[1:])):
                continue
            # resourceNames restrict named-object access, not all-list access.
            read_secrets = 'RBAC_SECRET_READ_PERMISSION' in indicators or 'RBAC_NAMED_SECRET_READ_PERMISSION' in indicators
            mutate_binding = covers_group_any(groups, 'rbac.authorization.k8s.io') and bool(resources & {'rolebindings', 'clusterrolebindings', '*'}) and bool(verbs & {'create', 'update', 'patch', '*'})
            deploy_pod = (covers_group_any(groups, '') and bool(resources & {'pods', '*'}) or covers_group_any(groups, 'apps') and 'deployments' in resources) and bool(verbs & {'create', '*'})
            candidates = []
            if read_secrets:
                candidates.append(('POTENTIAL_SECRET_ACCESS', 'high', 'Kubernetes API read of Secret objects', 'T1078'))
            if mutate_binding:
                candidates.append(('POTENTIAL_RBAC_MUTATION', 'critical', 'Kubernetes RBAC binding modification', 'T1078'))
            if 'RBAC_ESCALATE_PERMISSION' in indicators:
                candidates.append(('POTENTIAL_RBAC_ESCALATE', 'critical', 'Potential permission to create/update Roles beyond own granted rights', 'T1078'))
            if 'RBAC_BIND_PERMISSION' in indicators:
                candidates.append(('POTENTIAL_RBAC_BIND', 'critical', 'Potential permission to bind additional role privileges', 'T1078'))
            if 'RBAC_IMPERSONATE_PERMISSION' in indicators:
                candidates.append(('POTENTIAL_IDENTITY_IMPERSONATION', 'critical', 'Potential ability to impersonate Kubernetes identities', 'T1078'))
            if deploy_pod:
                candidates.append(('POTENTIAL_WORKLOAD_CREATION', 'high', 'Workload creation permission', 'T1610'))
            for rule, severity, effect, technique in candidates:
                key = workload, sa, grant['binding'], grant['role'], rule, grant['scope']
                if key in seen:
                    continue
                seen.add(key)
                preconditions = ['Hypothetical attacker code execution in the workload', 'Usable API credentials for the workload ServiceAccount', 'API server reachable and authorization rules applicable']
                if credential['credential_mount'] == 'unresolved_service_account':
                    preconditions.append('Referenced ServiceAccount must exist and permit a usable credential; absent from input snapshot')
                if rule == 'POTENTIAL_RBAC_MUTATION':
                    preconditions.append('API admission and RBAC bind/escalate safeguards also permit the requested modification')
                if rule in ('POTENTIAL_RBAC_ESCALATE', 'POTENTIAL_RBAC_BIND', 'POTENTIAL_IDENTITY_IMPERSONATION'):
                    preconditions.append('Authorized target, scope, and API-server policy permit the requested operation; activity is not observed')
                if rule == 'POTENTIAL_SECRET_ACCESS':
                    preconditions.append('Target Secret exists within the grant scope and meets resourceNames restrictions')
                results.append({'id': f'T-{len(results)+1:03}', 'rule': rule, 'severity': severity,
                    'classification': 'conditional_attack_transition', 'nodes': steps,
                    'initial_state': f'Assumed code execution in {workload}', 'possible_effect': effect,
                    'preconditions': preconditions, 'credential_mount': credential['credential_mount'],
                    'credential_evidence': credential,
                    'explainability': {
                        'configuration_fact': f"RBAC permission is granted to {sa} through {grant['binding']} and {grant['role']}.",
                        'hypothesis': f'If an attacker controls {workload} and obtains authorized API credentials, this grant may enable: {effect}.',
                        'unknowns': ['Attacker foothold is hypothetical', 'Credentials have not been observed', 'API reachability and runtime authorization have not been verified'],
                        'framework_mappings_are_detection_context_not_proof_of_attack': True,
                    },
                    'scope': grant['scope'], 'mitre_technique': technique,
                    'evidence': {'binding': grant['binding'], 'role': grant['role'], 'apiGroups': grant['apiGroups'], 'verbs': grant['verbs'],
                                 'resources': grant['resources'], 'resourceNames': grant['resourceNames']},
                    'confidence': 'conditional; not an observed compromise'})
    return results
