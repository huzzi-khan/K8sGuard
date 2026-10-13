from app.scanner import parse_manifests, analyze

def scan(text):
    return analyze(parse_manifests(text.encode()))

BASE = '''apiVersion: v1
kind: ServiceAccount
metadata: {name: worker, namespace: alpha}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: {name: secret-reader}
rules:
- apiGroups: ['']
  resources: [secrets]
  verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: grant, namespace: alpha}
subjects:
- kind: ServiceAccount
  name: worker
  namespace: alpha
roleRef: {kind: ClusterRole, name: secret-reader, apiGroup: rbac.authorization.k8s.io}
'''

def test_namespaced_clusterrole_binding():
    r=scan(BASE)
    assert len(r['effective_permissions']) == 1
    p=r['effective_permissions'][0]
    assert p['subject']=='ServiceAccount/alpha/worker'
    assert p['scope']=='alpha'
    assert any(x['rule']=='EFFECTIVE_SECRET_READ' for x in r['findings'])

def test_clusterrolebinding_applies_clusterwide():
    data=BASE.replace('kind: RoleBinding\nmetadata: {name: grant, namespace: alpha}', 'kind: ClusterRoleBinding\nmetadata: {name: grant}')
    r=scan(data)
    assert r['effective_permissions'][0]['scope']=='*'

def test_missing_role_is_not_silent_zero():
    r=scan(BASE.replace('name: secret-reader, apiGroup:', 'name: missing-role, apiGroup:'))
    assert not r['effective_permissions']
    assert any('role not supplied' in x['reason'] for x in r['unresolved_references'])

def test_different_namespace_subject_keeps_identity():
    r=scan(BASE.replace('name: worker\n  namespace: alpha\nroleRef:', 'name: worker\n  namespace: beta\nroleRef:'))
    assert r['effective_permissions'][0]['subject']=='ServiceAccount/beta/worker'
    assert r['effective_permissions'][0]['scope']=='alpha'

def test_resource_names_restriction_no_broad_secret_read_flag():
    r=scan(BASE.replace('  verbs: [get]', '  verbs: [get]\n  resourceNames: [specific-secret]'))
    assert not any(x['rule']=='EFFECTIVE_SECRET_READ' for x in r['findings'])
