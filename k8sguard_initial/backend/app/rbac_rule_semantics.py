"""Conservative Kubernetes RBAC resource/verb semantics for static assessment.

API groups and subresources matter: a custom API group resource named ``secrets``
should not be treated as core v1 Secrets; ``pods/exec`` requires the core group.
Wildcard grants are treated as potential broad capabilities, not enumerated APIs.
"""
from __future__ import annotations

RBAC_GROUP = 'rbac.authorization.k8s.io'


def covers_group(api_group: str, expected: str) -> bool:
    return api_group in ('*', expected)


def covers_resource(resource: str, expected: str) -> bool:
    return resource in ('*', expected)


def covers_verb(verb: str, expected: str) -> bool:
    return verb in ('*', expected)


def indicators_for_permission(api_group: str, resource: str, verb: str, resource_names: list[str]) -> list[str]:
    """Classify *one explicit grant*, without treating unknown names as core resources."""
    indicators = []
    if '*' in (api_group, resource, verb):
        indicators.append('RBAC_WILDCARD_PERMISSION')
    if covers_group(api_group, '') and covers_resource(resource, 'secrets') and verb in ('get', 'list', 'watch', '*'):
        # resourceNames constraints can restrict get/list/watch, but a named
        # Secret read may still matter; don't label that as unrestricted read.
        indicators.append('RBAC_NAMED_SECRET_READ_PERMISSION' if resource_names else 'RBAC_SECRET_READ_PERMISSION')
    if covers_group(api_group, RBAC_GROUP) and resource in ('roles', 'clusterroles', 'rolebindings', 'clusterrolebindings', '*') and verb in ('create', 'update', 'patch', 'delete', '*'):
        indicators.append('RBAC_ACCESS_CONTROL_MUTATION_PERMISSION')
    if covers_group(api_group, '') and resource in ('pods/exec', 'pods/attach', '*') and verb in ('create', '*'):
        indicators.append('RBAC_POD_EXEC_PERMISSION')
    # Kubernetes RBAC special verbs have specific authorization implications.
    # They remain enabling permissions, not evidence that escalation occurred.
    if covers_group(api_group, RBAC_GROUP) and resource in ('roles', 'clusterroles', '*') and verb in ('escalate', '*'):
        indicators.append('RBAC_ESCALATE_PERMISSION')
    if covers_group(api_group, RBAC_GROUP) and resource in ('roles', 'clusterroles', '*') and verb in ('bind', '*'):
        indicators.append('RBAC_BIND_PERMISSION')
    if verb in ('impersonate', '*') and (
        (covers_group(api_group, '') and resource in ('users', 'groups', 'serviceaccounts', '*')) or
        (covers_group(api_group, 'authentication.k8s.io') and resource in ('userextras', 'uids', '*'))
    ):
        indicators.append('RBAC_IMPERSONATE_PERMISSION')
    return indicators


def indicators_for_rule(grant: dict) -> set[str]:
    """Union of exactly declared API-group/resource/verb combinations."""
    return {indicator for group in grant.get('apiGroups', [''])
            for resource in grant.get('resources', [])
            for verb in grant.get('verbs', [])
            for indicator in indicators_for_permission(group, resource, verb, grant.get('resourceNames', []))}
