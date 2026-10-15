"""Conservative RBAC permission resolution from offline Kubernetes manifests.

Only declared ServiceAccount subjects are modeled. Absent referenced roles are
reported as unresolved, not interpreted as no access in the live cluster.
"""
from __future__ import annotations
from typing import Any
import networkx as nx
from .rbac_rule_semantics import indicators_for_rule


def ns(obj: dict) -> str:
    return obj.get('metadata', {}).get('namespace', 'default')


def obj_id(kind: str, namespace: str, name: str) -> str:
    return f'{kind}/{namespace}/{name}'


def normalized_rule(rule: dict, scope: str) -> dict:
    return {
        'apiGroups': sorted(set(rule.get('apiGroups') or [''])),
        'resources': sorted(set(rule.get('resources') or [])),
        'verbs': sorted(set(rule.get('verbs') or [])),
        'resourceNames': sorted(set(rule.get('resourceNames') or [])),
        'nonResourceURLs': sorted(set(rule.get('nonResourceURLs') or [])),
        'scope': scope,
    }


def collect_effective_access(docs: list[dict[str, Any]], graph: nx.DiGraph) -> tuple[list[dict], list[dict]]:
    roles = {}
    service_accounts: set[str] = set()
    for obj in docs:
        kind = obj['kind']
        meta = obj['metadata']
        name = meta['name']
        namespace = 'cluster' if kind == 'ClusterRole' else ns(obj)
        if kind in ('Role', 'ClusterRole'):
            roles[(kind, namespace, name)] = obj
        elif kind == 'ServiceAccount':
            service_accounts.add(obj_id('ServiceAccount', ns(obj), name))

    # ClusterRole aggregation: union matching ClusterRoles' declared rules.
    # Unlike API-server aggregation, this is a one-pass offline snapshot;
    # missing labels/roles and malformed selectors produce unresolved entries.
    unresolved: list[dict] = []
    def role_rules(kind: str, namespace: str, name: str, visited: frozenset = frozenset()):
        key = (kind, namespace, name)
        if key in visited:
            unresolved.append({'reference': str(key), 'reason': 'cyclic ClusterRole aggregation'})
            return []
        role = roles.get(key)
        if role is None:
            unresolved.append({'reference': obj_id(*key), 'reason': 'role not supplied in manifest snapshot'})
            return []
        rules = list(role.get('rules') or [])
        if kind == 'ClusterRole':
            selectors = ((role.get('aggregationRule') or {}).get('clusterRoleSelectors') or [])
            for selector in selectors:
                if selector.get('matchExpressions'):
                    unresolved.append({'reference': obj_id(*key), 'reason': 'matchExpressions aggregation selector not implemented'})
                    continue
                labels = selector.get('matchLabels') or {}
                for rkey, other in roles.items():
                    if rkey[0] != 'ClusterRole' or rkey == key:
                        continue
                    if labels and all((other.get('metadata', {}).get('labels') or {}).get(k) == v for k, v in labels.items()):
                        rules += role_rules(*rkey, visited | {key})
        return rules

    grants: list[dict] = []
    for binding in docs:
        kind = binding['kind']
        if kind not in ('RoleBinding', 'ClusterRoleBinding'):
            continue
        bind_ns = 'cluster' if kind == 'ClusterRoleBinding' else ns(binding)
        bid = obj_id(kind, bind_ns, binding['metadata']['name'])
        ref = binding.get('roleRef') or {}
        rolekind, rolename = ref.get('kind'), ref.get('name')
        if rolekind not in ('Role', 'ClusterRole') or not rolename or (kind == 'ClusterRoleBinding' and rolekind != 'ClusterRole'):
            unresolved.append({'reference': bid, 'reason': 'invalid roleRef for binding'})
            continue
        role_ns = 'cluster' if rolekind == 'ClusterRole' else bind_ns
        roleid = obj_id(rolekind, role_ns, rolename)
        graph.add_node(bid, label=binding['metadata']['name'], kind=kind, namespace=bind_ns)
        graph.add_node(roleid, label=rolename, kind=rolekind, namespace=role_ns)
        graph.add_edge(bid, roleid, relation='grants_role')
        for subject in binding.get('subjects') or []:
            if subject.get('kind') != 'ServiceAccount':
                # User/Group identity resolution is deferred; explicit limitation.
                unresolved.append({'reference': bid, 'reason': f"subject kind {subject.get('kind', 'unknown')} not modeled"})
                continue
            subject_ns = subject.get('namespace', bind_ns if kind == 'RoleBinding' else None)
            if not subject_ns or not subject.get('name'):
                unresolved.append({'reference': bid, 'reason': 'ServiceAccount subject namespace/name missing'})
                continue
            sid = obj_id('ServiceAccount', subject_ns, subject['name'])
            graph.add_node(sid, kind='ServiceAccount', label=subject['name'], namespace=subject_ns)
            graph.add_edge(sid, bid, relation='bound_by')
            if sid not in service_accounts:
                unresolved.append({'reference': sid, 'reason': 'ServiceAccount not present in snapshot'})
            # ClusterRole bound through RoleBinding remains namespaced.
            scope = '*' if kind == 'ClusterRoleBinding' else bind_ns
            for rule in role_rules(rolekind, role_ns, rolename):
                grant = {'subject': sid, 'binding': bid, 'role': roleid, **normalized_rule(rule, scope)}
                grants.append(grant)
    grants.sort(key=lambda g: (g['subject'], g['binding'], g['role'], str(g['resources']), str(g['verbs'])))
    return grants, unresolved


def grant_findings(grants: list[dict]) -> list[dict]:
    findings = []
    seen = set()
    for grant in grants:
        indicators = indicators_for_rule(grant)
        rules = []
        if 'RBAC_WILDCARD_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_RBAC_WILDCARD', 'high', 'Binding grants wildcard permissions'))
        if 'RBAC_SECRET_READ_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_SECRET_READ', 'high', 'ServiceAccount can read Secrets in the indicated scope'))
        if 'RBAC_ACCESS_CONTROL_MUTATION_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_RBAC_MUTATION', 'critical', 'ServiceAccount can modify access-control resources'))
        if 'RBAC_POD_EXEC_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_POD_EXEC', 'high', 'ServiceAccount may initiate pod exec/attach requests'))
        if 'RBAC_ESCALATE_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_RBAC_ESCALATE', 'critical', 'ServiceAccount has RBAC escalate authorization for Roles or ClusterRoles'))
        if 'RBAC_BIND_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_RBAC_BIND', 'critical', 'ServiceAccount has RBAC bind authorization for Roles or ClusterRoles'))
        if 'RBAC_IMPERSONATE_PERMISSION' in indicators:
            rules.append(('EFFECTIVE_RBAC_IMPERSONATE', 'critical', 'ServiceAccount has identity impersonation authorization'))
        for rule, sev, description in rules:
            key = (grant['subject'], grant['binding'], rule, str(grant['resources']), str(grant['verbs']))
            if key in seen:
                continue
            seen.add(key)
            findings.append({'id': f'RB-{len(findings)+1:03}', 'rule': rule, 'severity': sev,
                             'resource': grant['subject'], 'description': description,
                             'evidence': {'binding': grant['binding'], 'role': grant['role'],
                                          'scope': grant['scope'], 'apiGroups': grant['apiGroups'],
                                          'resources': grant['resources'], 'verbs': grant['verbs'],
                                          'resourceNames': grant['resourceNames']}})
    return findings
