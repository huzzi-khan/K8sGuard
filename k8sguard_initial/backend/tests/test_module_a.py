from pathlib import Path
from app.scanner import analyze, parse_manifests

FIXTURE = Path(__file__).resolve().parents[2] / 'fixtures' / 'operator_and_paths.yaml'

def result():
    return analyze(parse_manifests(FIXTURE.read_bytes()))

def test_effective_capability_path_exists():
    r=result()
    p=next(p for p in r['attack_paths'] if p['rule']=='SECRET_READ_CAPABILITY')
    assert p['nodes'][0]=='Deployment/app-ns/data-service'
    assert p['nodes'][-1]=='Role/app-ns/secrets-reader'
    assert p['classification']=='capability_path'

def test_operator_cross_scope_reference_verified():
    r=result()
    assert any(x['status']=='resolved' and x['cross_scope'] for x in r['operator_references'])
    assert any(f['rule']=='CROSS_SCOPE_OPERATOR_REFERENCE' for f in r['findings'])

def test_missing_target_is_unresolved_not_confirmed():
    docs=parse_manifests(FIXTURE.read_bytes())
    docs=[d for d in docs if d['kind']!='ClusterIssuer']
    r=analyze(docs)
    assert any(x['status']=='unresolved' for x in r['operator_references'])
    assert not any(f['rule']=='CROSS_SCOPE_OPERATOR_REFERENCE' for f in r['findings'])

def test_workload_and_networkpolicy_inventory():
    r=result()
    assert any(f['rule']=='PRIVILEGE_ESCALATION_ALLOWED' for f in r['findings'])
    assert any(p['policy_types']==['Ingress'] for p in r['network_policies'])

def test_no_fabricated_exploit_path_when_no_binding():
    docs=parse_manifests(FIXTURE.read_bytes())
    docs=[d for d in docs if d['kind']!='RoleBinding']
    assert analyze(docs)['attack_paths']==[]
