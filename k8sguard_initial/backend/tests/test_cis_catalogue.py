from app.cis_catalogue import candidate, RULE_TOPICS, CURRENT_EDITION
from app.scanner import analyze


def test_latest_edition_identified_but_candidate_not_claimed_as_audit():
    assert CURRENT_EDITION == '2.1.0'
    info = candidate('secrets_access')
    assert info['control_id'] == '5.1.2'
    assert info['benchmark_version'] is None
    assert 'pending_v2.1_primary_review' in info['mapping_status']


def test_graph_assessment_exposes_traceable_candidate_mapping():
    docs = [{'apiVersion':'rbac.authorization.k8s.io/v1','kind':'Role',
             'metadata':{'name':'secrets','namespace':'demo'},
             'rules':[{'apiGroups':[''], 'resources':['secrets'], 'verbs':['get']}]}]
    result = analyze(docs)
    mapping = next(f['cis_kubernetes'][0] for f in result['findings'] if f['rule']=='RBAC_SECRET_READ')
    assert mapping['control_id']=='5.1.2'
    assert mapping['assessment_type']=='local_static_indicator_not_cis_compliance'


def test_privileged_pod_check_has_candidate_not_verified_control():
    docs = [{'apiVersion':'v1','kind':'Pod','metadata':{'name':'p','namespace':'demo'},
             'spec':{'containers':[{'name':'c','image':'nginx','securityContext':{'privileged':True}}]}}]
    checks = analyze(docs)['cis_checks']
    c = next(c for c in checks if c['rule_id']=='K8SG-CIS-PRIVILEGED')
    assert c['status']=='fail'
    assert c['control_candidate']['control_id']=='5.2.1'
    assert c['cis_control_id'] is None
