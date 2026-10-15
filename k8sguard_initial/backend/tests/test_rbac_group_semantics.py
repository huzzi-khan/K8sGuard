"""Secure/insecure/ambiguous controls: negative cases must not become red edges."""
from app.scanner import analyze


def docs(group='', resources=('secrets',), verbs=('get',), resource_names=()):
    return [
        {'apiVersion':'v1','kind':'ServiceAccount','metadata':{'name':'reader','namespace':'team'}},
        {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role','metadata':{'name':'reader-role','namespace':'team'},
         'rules':[{'apiGroups':[group],'resources':list(resources),'verbs':list(verbs),'resourceNames':list(resource_names)}]},
        {'apiVersion':'rbac.authorization.k8s.io/v1','kind':'RoleBinding','metadata':{'name':'bind','namespace':'team'},
         'roleRef':{'kind':'Role','name':'reader-role'},
         'subjects':[{'kind':'ServiceAccount','namespace':'team','name':'reader'}]},
    ]


def rules(data):
    return {a['rule'] for a in data['graph_assessments']}


def test_custom_secrets_group_not_core_secret_read():
    result = analyze(docs('example.io'))
    assert 'EFFECTIVE_SECRET_READ' not in rules(result)
    assert not any('RBAC_SECRET_READ_PERMISSION' in p['indicators'] for p in result['permission_grants'])


def test_core_secret_read_maps_to_risky_authorization_edge():
    result = analyze(docs())
    assert 'EFFECTIVE_SECRET_READ' in rules(result)
    assert any(e['security_state'] == 'risk' and e['relation'] == 'grants_role' for e in result['edges'])


def test_named_secret_is_not_broad_secret_read():
    result = analyze(docs(resource_names=('named-secret',)))
    assert 'EFFECTIVE_SECRET_READ' not in rules(result)
    assert 'RBAC_NAMED_SECRET_READ_PERMISSION' in result['permission_grants'][0]['indicators']


def test_core_groups_do_not_trigger_rbac_mutation():
    result = analyze(docs('', ('roles',), ('update',)))
    assert 'EFFECTIVE_RBAC_MUTATION' not in rules(result)


def test_rbac_api_group_mutation_is_flagged():
    result = analyze(docs('rbac.authorization.k8s.io', ('rolebindings',), ('create',)))
    assert 'EFFECTIVE_RBAC_MUTATION' in rules(result)


def test_non_core_pods_exec_not_core_exec():
    result = analyze(docs('example.io', ('pods/exec',), ('create',)))
    assert 'EFFECTIVE_POD_EXEC' not in rules(result)


def test_core_pods_exec_is_flagged():
    result = analyze(docs('', ('pods/exec',), ('create',)))
    assert 'EFFECTIVE_POD_EXEC' in rules(result)


def test_read_only_configmaps_not_flagged_as_risky():
    result = analyze(docs('', ('configmaps',), ('get',)))
    assert not any(a['classification']=='detected_risky_configuration' for a in result['graph_assessments'])
    assert all(e['security_state'] != 'risk' for e in result['edges'] if e['relation']=='grants_role')


def test_wildcard_group_with_named_resource_can_enable_core_secret_read():
    result = analyze(docs('*', ('secrets',), ('get',)))
    assert 'EFFECTIVE_SECRET_READ' in rules(result)
    assert 'EFFECTIVE_RBAC_WILDCARD' in rules(result)


def test_custom_api_role_node_is_not_misclassified_as_core_secret_read():
    result = analyze(docs('example.io'))
    assert 'RBAC_SECRET_READ' not in {f['rule'] for f in result['findings']}
    assert not any(n['security_state']=='risk' for n in result['nodes'] if n['id']=='Role/team/reader-role')


def test_named_secret_role_not_misclassified_as_broad_access():
    result = analyze(docs(resource_names=('named-secret',)))
    assert 'RBAC_SECRET_READ' not in {f['rule'] for f in result['findings']}
