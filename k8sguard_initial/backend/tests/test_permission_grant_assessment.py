from app.rbac_grant_assessment import permission_records
from app.scanner import analyze


def resource(kind, name, **fields):
    return {'apiVersion': 'rbac.authorization.k8s.io/v1' if kind != 'ServiceAccount' else 'v1',
            'kind': kind, 'metadata': {'name': name, 'namespace': 'demo'}, **fields}


def setup_docs(verbs=('get',), resources=('secrets',), names=()):
    return [resource('ServiceAccount', 'reader'),
            resource('Role', 'access', rules=[{'apiGroups': [''], 'resources': list(resources), 'verbs': list(verbs), 'resourceNames': list(names)}]),
            resource('RoleBinding', 'grant', roleRef={'kind': 'Role', 'name': 'access'},
                     subjects=[{'kind': 'ServiceAccount', 'name': 'reader', 'namespace': 'demo'}])]


def test_grants_identify_individual_verb_and_resource():
    r = analyze(setup_docs(('get', 'list'), ('secrets', 'pods')))
    grants = r['permission_grants']
    assert {(p['resource'], p['verb']) for p in grants} == {('secrets', 'get'), ('secrets', 'list'), ('pods', 'get'), ('pods', 'list')}
    assert all(p['subject'] == 'ServiceAccount/demo/reader' and p['scope'] == 'demo' for p in grants)
    assert sum('RBAC_SECRET_READ_PERMISSION' in p['indicators'] for p in grants) == 2
    assert all('grant_id' in p for p in grants)
    assert any(a['permission_grant_ids'] for a in r['graph_assessments'] if a['rule'] == 'EFFECTIVE_SECRET_READ')


def test_named_secret_read_is_distinct_from_broad_secret_read():
    r = analyze(setup_docs(names=('specific',)))
    p = r['permission_grants'][0]
    assert p['resource_names'] == ['specific']
    assert 'RBAC_NAMED_SECRET_READ_PERMISSION' in p['indicators']
    assert 'RBAC_SECRET_READ_PERMISSION' not in p['indicators']
    assert not any(a['rule'] == 'EFFECTIVE_SECRET_READ' for a in r['graph_assessments'])


def test_scoped_and_cluster_grants_do_not_collapse():
    docs = setup_docs()
    docs += [resource('ClusterRole', 'global', rules=[{'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get']}]),
             resource('ClusterRoleBinding', 'global-bind', roleRef={'kind': 'ClusterRole', 'name': 'global'},
                      subjects=[{'kind': 'ServiceAccount', 'namespace': 'demo', 'name': 'reader'}])]
    grants = analyze(docs)['permission_grants']
    assert set(p['scope'] for p in grants) == {'demo', '*'}
    assert len({p['grant_id'] for p in grants}) == len(grants)


def test_non_risky_permissions_remain_unassessed_not_safe():
    grants = permission_records([{'subject': 'ServiceAccount/demo/reader', 'binding': 'RoleBinding/demo/g',
       'role': 'Role/demo/r', 'scope': 'demo', 'apiGroups': [''], 'resources': ['configmaps'],
       'verbs': ['get'], 'resourceNames': []}])
    assert grants[0]['risk_state'] == 'unassessed'
    assert not grants[0]['indicators']


def test_grant_ids_are_stable_regardless_input_order():
    r = analyze(setup_docs(('get', 'list')))
    s = analyze(setup_docs(('list', 'get')))
    assert r['permission_grants'] == s['permission_grants']
