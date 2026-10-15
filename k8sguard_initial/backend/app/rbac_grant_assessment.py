"""Permission-level RBAC security evidence; static grants, not observed activity.

Avoid expanding wildcard permissions into imagined concrete API resources.
Each record describes one explicit API-group/resource/verb combination, preserving
binding, role, ServiceAccount, effective scope and resource-name restriction.
"""
from __future__ import annotations
import hashlib
import json
from .rbac_rule_semantics import indicators_for_permission


def permission_records(grants: list[dict]) -> list[dict]:
    out = {}
    for grant in grants:
        for api_group in grant.get('apiGroups', ['']):
            for resource in grant.get('resources', []):
                for verb in grant.get('verbs', []):
                    detail = {key: grant[key] for key in ('subject', 'binding', 'role', 'scope')}
                    detail.update(api_group=api_group, resource=resource, verb=verb,
                                  resource_names=list(grant.get('resourceNames', [])))
                    # Explicitly distinguish non-resource URL rules from resource grants.
                    key = json.dumps(detail, sort_keys=True, separators=(',', ':'))
                    identifier = 'PG-' + hashlib.sha256(key.encode()).hexdigest()[:16]
                    indicators = indicators_for_permission(api_group, resource, verb, detail['resource_names'])
                    out[identifier] = {**detail, 'grant_id': identifier, 'indicators': indicators,
                        'risk_state': 'risk' if indicators else 'unassessed',
                        'interpretation': 'Static declared authorization, subject to admission and runtime prerequisites.'}
    return [out[k] for k in sorted(out)]
