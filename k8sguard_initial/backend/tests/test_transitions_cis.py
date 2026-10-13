from pathlib import Path
from app.scanner import analyze, parse_manifests

FIXTURE = Path(__file__).resolve().parents[2] / 'fixtures' / 'operator_and_paths.yaml'

def read():
    return parse_manifests(FIXTURE.read_bytes())

def test_transitions_require_binding():
    docs = read()
    output = analyze(docs)
    assert any(t['rule'] == 'POTENTIAL_SECRET_ACCESS' for t in output['attack_transitions'])
    assert all(t['classification']=='conditional_attack_transition' and t['preconditions'] for t in output['attack_transitions'])
    unbound = [d for d in docs if d['kind'] != 'RoleBinding']
    assert not analyze(unbound)['attack_transitions']

def test_automount_opt_out_blocks_transitions():
    docs = read()
    for d in docs:
        if d['kind'] == 'Deployment':
            d['spec']['template']['spec']['automountServiceAccountToken'] = False
    assert not analyze(docs)['attack_transitions']

def test_cis_unset_is_unknown():
    docs = read()
    checks = analyze(docs)['cis_checks']
    assert checks
    assert any(c['status']=='unknown' for c in checks)
    assert all(c['cis_control_id'] is None and c['benchmark_version'] is None for c in checks)

def test_cis_explicit_privileged_fails():
    docs = read()
    for d in docs:
        if d['kind'] == 'Deployment':
            d['spec']['template']['spec']['containers'][0].setdefault('securityContext',{})['privileged'] = True
    checks = analyze(docs)['cis_checks']
    assert any(c['rule_id']=='K8SG-CIS-PRIVILEGED' and c['status']=='fail' for c in checks)
