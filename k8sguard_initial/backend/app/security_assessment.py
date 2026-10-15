"""Evidence-linked graph assessment. Not proof of exploitation or CIS certification.

The graph model contains relationship edges (not individual permission edges).
An RBAC finding is therefore attached to the *binding -> role* authorization
relationship, with the effective subject and grant scope retained as evidence.
"""
from __future__ import annotations
from collections import defaultdict

SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}

# Conditions already evaluated by the scanner. These are risky configurations,
# not observed exploits. MITRE/CIS references come from the finding crosswalk.
RISK_RULES = {
    'EFFECTIVE_RBAC_WILDCARD', 'EFFECTIVE_SECRET_READ',
    'EFFECTIVE_RBAC_MUTATION', 'EFFECTIVE_POD_EXEC',
    'EFFECTIVE_RBAC_ESCALATE', 'EFFECTIVE_RBAC_BIND', 'EFFECTIVE_RBAC_IMPERSONATE',
    'PRIVILEGED_CONTAINER', 'PRIVILEGE_ESCALATION_ALLOWED',
    'DANGEROUS_CAPABILITIES', 'POD_HOSTPATH',
    'POD_HOSTPID', 'POD_HOSTIPC', 'POD_HOSTNETWORK',
    'RBAC_WILDCARD', 'RBAC_SECRET_READ',
}


def assess_graph(result: dict) -> dict:
    """Attach finding evidence to specific graph elements without altering topology."""
    findings = result.get('findings', [])
    nodes = result.get('nodes', [])
    edges = result.get('edges', [])
    node_index = {n['id']: n for n in nodes}
    edge_index = {(e['source'], e['target']): e for e in edges}
    assessments = []
    linked = defaultdict(list)

    for finding in findings:
        rule = finding.get('rule', '')
        resource = finding.get('resource')
        ev = finding.get('evidence') or {}
        severity = finding.get('severity', 'info')
        risky = rule in RISK_RULES
        # Cross-scope operator references require context; scope crossing alone
        # is not evidence of an authorization bypass.
        conditional = rule == 'CROSS_SCOPE_OPERATOR_REFERENCE'
        if not risky and not conditional:
            continue
        edge_key = None
        if rule.startswith('EFFECTIVE_') and ev.get('binding') and ev.get('role'):
            candidate = (ev['binding'], ev['role'])
            if candidate in edge_index:
                edge_key = candidate
        elif conditional and ev.get('target'):
            candidate = (ev.get('source', resource), ev['target'])
            if candidate in edge_index:
                edge_key = candidate
        target_type = 'edge' if edge_key else 'node'
        target = {'source': edge_key[0], 'target': edge_key[1]} if edge_key else {'id': resource}
        if not edge_key and resource not in node_index:
            continue
        classification = 'conditional_review' if conditional else 'detected_risky_configuration'
        item = {
            'id': f'GA-{len(assessments)+1:04}', 'finding_id': finding.get('id'),
            'rule': rule, 'severity': severity, 'classification': classification,
            'confidence': 'verified_configuration_requires_context' if conditional else 'configuration_evidence',
            'target_type': target_type, 'target': target,
            'resource': resource, 'evidence': ev,
            'permission_grant_ids': sorted(p['grant_id'] for p in result.get('permission_grants', [])
                if p['subject'] == resource and p['binding'] == ev.get('binding')
                and p['role'] == ev.get('role') and p['scope'] == ev.get('scope')
                and bool(set(p['indicators']) & {
                    'EFFECTIVE_RBAC_WILDCARD': {'RBAC_WILDCARD_PERMISSION'},
                    'EFFECTIVE_SECRET_READ': {'RBAC_SECRET_READ_PERMISSION'},
                    'EFFECTIVE_RBAC_MUTATION': {'RBAC_ACCESS_CONTROL_MUTATION_PERMISSION'},
                    'EFFECTIVE_POD_EXEC': {'RBAC_POD_EXEC_PERMISSION'},
                    'EFFECTIVE_RBAC_ESCALATE': {'RBAC_ESCALATE_PERMISSION'},
                    'EFFECTIVE_RBAC_BIND': {'RBAC_BIND_PERMISSION'},
                    'EFFECTIVE_RBAC_IMPERSONATE': {'RBAC_IMPERSONATE_PERMISSION'},
                }.get(rule, set()))),
            'description': finding.get('description'),
            'mitre_attack': finding.get('mitre_attack', []),
            'cis_kubernetes': finding.get('cis_kubernetes', []),
            'interpretation': ('Cross-scope reference exists; review its security implications before treating it as risky.'
                               if conditional else 'Flagged configuration/capability; not proof of exploitation.'),
        }
        assessments.append(item)
        key = ('edge', *edge_key) if edge_key else ('node', resource)
        linked[key].append(item)
        if edge_key:
            # Subject is itself significant evidence for a grant, yet the
            # edge is shared by multiple ServiceAccounts.
            if resource in node_index:
                linked[('node', resource)].append(item)

    def decorate(obj, items):
        if not items:
            obj['security_state'] = 'unassessed'
            obj['assessment_ids'] = []
            return
        risky = [a for a in items if a['classification'] == 'detected_risky_configuration']
        obj['security_state'] = 'risk' if risky else 'review'
        obj['assessment_ids'] = list(dict.fromkeys(a['id'] for a in items))
        chosen = max(risky or items, key=lambda x: SEVERITY_ORDER.get(x['severity'], -1))
        obj['highest_severity'] = chosen['severity']

    for node in nodes:
        decorate(node, linked[('node', node['id'])])
    for edge in edges:
        decorate(edge, linked[('edge', edge['source'], edge['target'])])

    result['graph_assessments'] = assessments
    result['permission_grant_summary'] = {
        'total': len(result.get('permission_grants', [])),
        'flagged': sum(bool(p['indicators']) for p in result.get('permission_grants', [])),
        'note': 'One record per explicit API-group/resource/verb; wildcard values are not expanded.'
    }
    result['graph_assessment_summary'] = {
        'risk': sum(a['classification'] == 'detected_risky_configuration' for a in assessments),
        'conditional_review': sum(a['classification'] == 'conditional_review' for a in assessments),
        'assessed_edges': sum(e['security_state'] != 'unassessed' for e in edges),
        'unassessed_edges': sum(e['security_state'] == 'unassessed' for e in edges),
    }
    result['limitations'].append('Unassessed edges are not certified safe; red means a rule-supported risk, not proven exploitation.')
    result['limitations'].append('An RBAC grant may support multiple subjects; inspect assessment evidence to identify each affected ServiceAccount and scope.')
    return result
