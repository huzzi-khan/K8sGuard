from fastapi.testclient import TestClient
from app import main

client = TestClient(main.app, base_url='http://127.0.0.1')

def test_live_requires_token(monkeypatch):
    monkeypatch.setenv('K8SGUARD_LOCAL_SCAN_TOKEN', 'test-token')
    monkeypatch.setenv('K8SGUARD_CONTEXT', 'kind-example')
    assert client.post('/api/scans/live').status_code == 403
    assert client.post('/api/scans/live', headers={'X-Local-Scan-Token': 'wrong'}).status_code == 403

def test_live_scan_uses_existing_analyzer(monkeypatch):
    monkeypatch.setenv('K8SGUARD_LOCAL_SCAN_TOKEN', 'test-token')
    monkeypatch.setenv('K8SGUARD_CONTEXT', 'kind-example')
    fixture = {'apiVersion':'v1','kind':'Namespace','metadata':{'name':'example'}}
    monkeypatch.setattr(main, 'collect_snapshot', lambda context: ([fixture], ['NetworkPolicy: missing privileges']))
    r = client.post('/api/scans/live', headers={'X-Local-Scan-Token':'test-token'})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data['source'] == 'live_cluster'
    assert data['cluster_context'] == 'kind-example'
    assert data['collection_errors']
    assert data['nodes'] == client.get('/api/scans/'+data['scan_id']+'/graph').json()['nodes']

def test_live_empty_snapshot_is_error(monkeypatch):
    monkeypatch.setenv('K8SGUARD_LOCAL_SCAN_TOKEN', 'test-token')
    monkeypatch.setenv('K8SGUARD_CONTEXT', 'kind-example')
    monkeypatch.setattr(main, 'collect_snapshot', lambda context: ([], []))
    assert client.post('/api/scans/live', headers={'X-Local-Scan-Token':'test-token'}).status_code == 503
