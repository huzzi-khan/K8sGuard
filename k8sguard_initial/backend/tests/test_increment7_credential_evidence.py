from app.credential_evidence import workload_credential_context
from app.scanner import analyze


def scenario(pod_token=None, sa_token=None, include_sa=True):
    ns = 'lab'
    role = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'Role', 'metadata': {'namespace': ns, 'name': 'reader'}, 'rules': [{'apiGroups': [''], 'resources': ['secrets'], 'verbs': ['get']}]}
    binding = {'apiVersion': 'rbac.authorization.k8s.io/v1', 'kind': 'RoleBinding', 'metadata': {'namespace': ns, 'name': 'allow'}, 'roleRef': {'kind': 'Role', 'name': 'reader'}, 'subjects': [{'kind': 'ServiceAccount', 'namespace': ns, 'name': 'runner'}]}
    podspec = {'serviceAccountName': 'runner', 'containers': [{'name': 'app', 'image': 'busybox'}]}
    if pod_token is not None: podspec['automountServiceAccountToken'] = pod_token
    pod = {'apiVersion': 'v1', 'kind': 'Pod', 'metadata': {'namespace': ns, 'name': 'app'}, 'spec': podspec}
    docs = [role, binding, pod]
    if include_sa:
        sa = {'apiVersion': 'v1', 'kind': 'ServiceAccount', 'metadata': {'namespace': ns, 'name': 'runner'}}
        if sa_token is not None: sa['automountServiceAccountToken'] = sa_token
        docs.append(sa)
    return docs


def test_service_account_opt_out_suppresses_transition_but_not_rbac_grant():
    output = analyze(scenario(sa_token=False))
    assert output['attack_transitions'] == []
    assert any(f['rule'] == 'EFFECTIVE_SECRET_READ' for f in output['findings'])


def test_explicit_pod_enable_overrides_sa_opt_out():
    output = analyze(scenario(pod_token=True, sa_token=False))
    assert output['attack_transitions']
    evidence = output['attack_transitions'][0]['credential_evidence']
    assert evidence['credential_mount'] == 'enabled'
    assert evidence['decision_source'] == 'workload_spec'


def test_explicit_pod_disable_overrides_sa_enable():
    assert analyze(scenario(pod_token=False, sa_token=True))['attack_transitions'] == []


def test_sa_missing_remains_unresolved_not_a_verified_mount():
    output = analyze(scenario(include_sa=False))
    assert output['attack_transitions']
    transition = output['attack_transitions'][0]
    assert transition['credential_mount'] == 'unresolved_service_account'
    assert any('absent from input snapshot' in condition for condition in transition['preconditions'])
    assert transition['credential_evidence']['credentials_observed'] is False


def test_default_setting_with_present_sa_is_reported_as_kubernetes_default():
    transition = analyze(scenario())['attack_transitions'][0]
    assert transition['credential_mount'] == 'enabled_by_kubernetes_default'
    assert transition['explainability']['configuration_fact']
    assert transition['explainability']['hypothesis']
    assert len(transition['explainability']['unknowns']) >= 3
    assert transition['explainability']['framework_mappings_are_detection_context_not_proof_of_attack']


def test_credential_context_is_deterministic():
    docs = scenario(sa_token=False)
    assert workload_credential_context(docs) == workload_credential_context(docs)
