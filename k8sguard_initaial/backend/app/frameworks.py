"""Conservative ATT&CK/CIS crosswalk, not a CIS compliance certification.

CIS control IDs depend on benchmark release and target Kubernetes version.
This crosswalk deliberately uses stable topic names until a benchmark version is
selected and rule-by-rule requirements have been independently verified.
"""
from __future__ import annotations

MITRE = {
    'T1609': {'name': 'Container Administration Command', 'tactic': 'Execution'},
    'T1610': {'name': 'Deploy Container', 'tactic': 'Execution'},
    'T1611': {'name': 'Escape to Host', 'tactic': 'Privilege Escalation'},
    'T1613': {'name': 'Container and Resource Discovery', 'tactic': 'Discovery'},
    'T1078': {'name': 'Valid Accounts', 'tactic': 'Privilege Escalation'},
}

# Each link is a potential enabling condition, not proof the technique occurred.
RULES = {
    'RBAC_WILDCARD': (['T1078'], ['RBAC least privilege']),
    'RBAC_SECRET_READ': (['T1078'], ['RBAC least privilege / secrets access']),
    'SECRET_READ_CAPABILITY': (['T1078'], ['RBAC least privilege / secrets access']),
    'RBAC_BINDING_MUTATION_CAPABILITY': (['T1078'], ['RBAC least privilege']),
    'POD_EXEC_CAPABILITY': (['T1609'], ['RBAC least privilege']),
    'PRIVILEGED_CONTAINER': (['T1611'], ['Pod/container privilege restrictions']),
    'PRIVILEGE_ESCALATION_ALLOWED': (['T1611'], ['Pod/container privilege restrictions']),
    'DANGEROUS_CAPABILITIES': (['T1611'], ['Pod/container privilege restrictions']),
    'POD_HOSTPATH': (['T1611'], ['Pod/container privilege restrictions']),
    'POD_HOSTPID': (['T1611'], ['Pod/container host namespace restrictions']),
    'POD_HOSTIPC': (['T1611'], ['Pod/container host namespace restrictions']),
    'POD_HOSTNETWORK': (['T1611'], ['Pod/container host namespace restrictions']),
    'POD_TOKEN_AUTOMOUNT': (['T1078'], ['ServiceAccount token exposure']),
    'CROSS_SCOPE_OPERATOR_REFERENCE': ([], ['Cross-scope custom resource review']),
    'NETPOL_DENY_INGRESS': ([], ['NetworkPolicy segmentation']),
    'NETPOL_DENY_EGRESS': ([], ['NetworkPolicy segmentation']),
}

def tag(rule: str) -> dict:
    ids, topics = RULES.get(rule, ([], []))
    return {
        'mitre_attack': [{'technique_id': t, **MITRE[t], 'relationship': 'potential_enabler',
                          'url': f'https://attack.mitre.org/techniques/{t}/'} for t in ids],
        'cis_kubernetes': [{'topic': x, 'benchmark_version': None, 'control_id': None,
                            'status': 'candidate_mapping_requires_versioned_review'} for x in topics],
    }

def annotate(result: dict) -> dict:
    for key in ('findings', 'attack_paths'):
        for item in result.get(key, []):
            item.update(tag(item.get('rule', '')))
    # Technique nodes are semantic annotations, not possible reachability edges.
    used = {m['technique_id'] for item in result.get('findings', []) + result.get('attack_paths', [])
            for m in item['mitre_attack']}
    for technique_id in sorted(used):
        tid = f'MITRE/{technique_id}'
        result['nodes'].append({'id': tid, 'kind': 'MitreTechnique', 'label': f'{technique_id}: {MITRE[technique_id]["name"]}',
                                'namespace': 'framework'})
    for item in result.get('findings', []):
        for m in item['mitre_attack']:
            result['edges'].append({'source': item['resource'], 'target': f'MITRE/{m["technique_id"]}',
                                    'relation': 'potential_attack_technique', 'finding_id': item['id'],
                                    'semantic_only': True})
    result['frameworks'] = {'mitre_attack': {'matrix': 'Enterprise ATT&CK / Containers', 'techniques_used': sorted(used)},
                            'cis_kubernetes': {'benchmark_version': None,
                                               'status': 'topic_crosswalk_only; no control ID or compliance assertion'}}
    result['limitations'].append('MITRE edges indicate potential enabling conditions, not observed attacker behavior or confirmed exploit chains.')
    result['limitations'].append('CIS topics are indicative only; choose a benchmark version and verify exact control IDs before claiming compliance.')
    return result
