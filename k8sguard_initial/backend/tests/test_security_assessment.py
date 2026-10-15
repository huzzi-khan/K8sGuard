from app.security_assessment import assess_graph
from app.scanner import analyze, parse_manifests
from pathlib import Path

BASE = Path(__file__).resolve().parents[2] / 'fixtures'


def test_effective_rbac_finding_attaches_to_authorization_edge():
    data = analyze(parse_manifests((BASE / 'insecure.yaml').read_bytes()))
    related = [a for a in data['graph_assessments'] if a['rule'].startswith('EFFECTIVE_')]
    assert related
    for assessment in related:
        assert assessment['target_type'] == 'edge'
        assert assessment['target']['source'].split('/')[0] in ('RoleBinding', 'ClusterRoleBinding')
        assert assessment['evidence'].get('scope') is not None
    assert any(e['security_state'] == 'risk' for e in data['edges'])


def test_risk_is_not_automatically_assigned_to_ordinary_relationships():
    docs = [{'apiVersion':'v1', 'kind':'Pod', 'metadata':{'name':'ordinary','namespace':'demo'},
             'spec':{'containers':[{'name':'web','image':'nginx'}]}}]
    data = analyze(docs)
    use_edges = [e for e in data['edges'] if e.get('relation') == 'uses_service_account']
    assert use_edges and all(e['security_state'] == 'unassessed' for e in use_edges)


def test_cross_scope_reference_is_not_automatically_red():
    data = analyze(parse_manifests((BASE / 'operator_and_paths.yaml').read_bytes()))
    assessments = [a for a in data['graph_assessments'] if a['rule'] == 'CROSS_SCOPE_OPERATOR_REFERENCE']
    assert assessments
    assert all(a['classification'] == 'conditional_review' for a in assessments)
    assert all(a['target_type'] == 'edge' for a in assessments)


def test_assessments_include_no_fabricated_cis_control_ids():
    data = analyze(parse_manifests((BASE / 'insecure.yaml').read_bytes()))
    for a in data['graph_assessments']:
        assert all(mapping.get('benchmark_version') is None for mapping in a['cis_kubernetes'])
        assert all(mapping.get('mapping_status', '').endswith('pending_v2.1_primary_review') or mapping.get('control_id') is None for mapping in a['cis_kubernetes'])
