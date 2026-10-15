"""Increment 6: rule semantics, privilege prerequisites and API-group isolation."""
from app.rbac_rule_semantics import indicators_for_permission
from app.scanner import analyze


def doc(kind, name, namespace='demo', **extras):
    return {'apiVersion': 'rbac.authorization.k8s.io/v1' if kind in ('Role','RoleBinding') else 'v1',
            'kind': kind, 'metadata': {'name':name, 'namespace':namespace}, **extras}


def scenario(api_group, resource, verb, pod_automount=None):
    role = doc('Role', 'power', rules=[{'apiGroups':[api_group], 'resources':[resource], 'verbs':[verb]}])
    binding = doc('RoleBinding', 'link', roleRef={'kind':'Role','name':'power','apiGroup':'rbac.authorization.k8s.io'},
                  subjects=[{'kind':'ServiceAccount','name':'runner','namespace':'demo'}])
    sa = doc('ServiceAccount','runner')
    pod_spec = {'serviceAccountName':'runner','containers':[{'name':'app', 'image':'busybox'}]}
    if pod_automount is not None: pod_spec['automountServiceAccountToken']=pod_automount
    pod = doc('Pod', 'worker',spec=pod_spec)
    return analyze([role,binding,sa,pod])


def test_escalate_evidence_and_risky_edge():
    result=scenario('rbac.authorization.k8s.io','roles','escalate')
    grants=[p for p in result['permission_grants'] if 'RBAC_ESCALATE_PERMISSION' in p['indicators']]
    assert len(grants)==1
    assert (grants[0]['api_group'], grants[0]['resource'], grants[0]['verb']) == ('rbac.authorization.k8s.io','roles','escalate')
    assert any(a['rule']=='EFFECTIVE_RBAC_ESCALATE' and grants[0]['grant_id'] in a['permission_grant_ids'] and a['target_type']=='edge' for a in result['graph_assessments'])
    assert any(t['rule']=='POTENTIAL_RBAC_ESCALATE' for t in result['attack_transitions'])


def test_bind_special_verb():
    result=scenario('rbac.authorization.k8s.io','clusterroles','bind')
    assert any(f['rule']=='EFFECTIVE_RBAC_BIND' for f in result['findings'])
    assert any(t['rule']=='POTENTIAL_RBAC_BIND' for t in result['attack_transitions'])


def test_impersonate_subjects():
    result=scenario('','serviceaccounts','impersonate')
    assert any(f['rule']=='EFFECTIVE_RBAC_IMPERSONATE' for f in result['findings'])
    assert any(t['rule']=='POTENTIAL_IDENTITY_IMPERSONATION' for t in result['attack_transitions'])


def test_fake_special_resource_custom_group_not_flagged():
    for resource, verb in [('roles','escalate'),('clusterroles','bind'),('serviceaccounts','impersonate')]:
        result=scenario('sample.example.io',resource,verb)
        assert not any(f['rule'] in ('EFFECTIVE_RBAC_ESCALATE','EFFECTIVE_RBAC_BIND','EFFECTIVE_RBAC_IMPERSONATE') for f in result['findings'])


def test_fake_secret_custom_group_does_not_generate_transition():
    result=scenario('sample.example.io','secrets','get')
    assert not any(t['rule']=='POTENTIAL_SECRET_ACCESS' for t in result['attack_transitions'])


def test_fake_binding_custom_group_does_not_generate_transition():
    result=scenario('sample.example.io','rolebindings','create')
    assert not any(t['rule']=='POTENTIAL_RBAC_MUTATION' for t in result['attack_transitions'])


def test_automount_explicit_false_suppresses_escalation_transition():
    result=scenario('rbac.authorization.k8s.io','roles','escalate', pod_automount=False)
    assert any(f['rule']=='EFFECTIVE_RBAC_ESCALATE' for f in result['findings'])
    assert not any(t['rule']=='POTENTIAL_RBAC_ESCALATE' for t in result['attack_transitions'])


def test_exact_group_requirement_for_special_verbs():
    assert 'RBAC_BIND_PERMISSION' in indicators_for_permission('rbac.authorization.k8s.io','clusterroles','bind',[])
    assert 'RBAC_BIND_PERMISSION' not in indicators_for_permission('','clusterroles','bind',[])
