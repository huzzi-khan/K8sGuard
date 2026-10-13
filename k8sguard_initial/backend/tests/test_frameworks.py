from pathlib import Path
from app.scanner import analyze, parse_manifests
from app.frameworks import tag

BASE = Path(__file__).resolve().parents[2]/'fixtures'

def test_mitre_workload_mapping_and_graph_annotations():
    data = analyze(parse_manifests((BASE/'insecure.yaml').read_bytes()))
    privileged = [f for f in data['findings'] if f['rule']=='PRIVILEGED_CONTAINER']
    assert privileged
    assert privileged[0]['mitre_attack'][0]['technique_id']=='T1611'
    assert all(e.get('semantic_only') for e in data['edges'] if e['relation']=='potential_attack_technique')

def test_no_invented_cis_version_or_compliance():
    mapped=tag('POD_HOSTPATH')['cis_kubernetes'][0]
    assert mapped['control_id'] is None and mapped['benchmark_version'] is None

def test_no_technique_mapping_for_operator_reference_without_exploit():
    assert tag('CROSS_SCOPE_OPERATOR_REFERENCE')['mitre_attack']==[]

def test_annotation_retains_capability_path_classification():
    data=analyze(parse_manifests((BASE/'operator_and_paths.yaml').read_bytes()))
    assert any(p['classification']=='capability_path' for p in data['attack_paths'])
    assert all(p['mitre_attack'] for p in data['attack_paths'])
