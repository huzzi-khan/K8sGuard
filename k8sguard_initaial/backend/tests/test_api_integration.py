"""HTTP-level smoke tests for the complete offline scan workflow."""
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app, scans

client = TestClient(app)
FIXTURE = Path(__file__).resolve().parents[2] / 'fixtures' / 'operator_and_paths.yaml'

def test_upload_and_retrieve_scan():
    response = client.post('/api/scans/manifests', files={'file': ('fixture.yaml', FIXTURE.read_bytes(), 'application/yaml')})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result['scan_id'] in scans
    assert result['resources'] > 0
    assert isinstance(result['nodes'], list)
    assert isinstance(result['attack_transitions'], list)
    assert isinstance(result['cis_checks'], list)
    sid = result['scan_id']
    assert client.get(f'/api/scans/{sid}').json()['scan_id'] == sid
    assert client.get(f'/api/scans/{sid}/graph').json()['nodes'] == result['nodes']
    assert client.get(f'/api/scans/{sid}/findings').json() == result['findings']

def test_invalid_yaml_rejected():
    response = client.post('/api/scans/manifests', files={'file': ('bad.yaml', b'not: [valid', 'application/yaml')})
    assert response.status_code == 422

def test_missing_scan_is_404():
    assert client.get('/api/scans/missing-id').status_code == 404

def test_frontend_origins_allowed():
    for origin in ('http://localhost:5173', 'http://127.0.0.1:5173'):
        response = client.options('/api/scans/manifests', headers={
            'Origin':origin,
            'Access-Control-Request-Method':'POST',
            'Access-Control-Request-Headers':'content-type'})
        assert response.status_code == 200
        assert response.headers.get('access-control-allow-origin') == origin
