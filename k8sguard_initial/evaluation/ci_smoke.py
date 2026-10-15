"""Offline CI smoke test; never connects to a live Kubernetes cluster."""
from pathlib import Path
from fastapi.testclient import TestClient
from app.main import app

ROOT = Path(__file__).resolve().parents[1]
client = TestClient(app)
health = client.get('/health')
assert health.status_code == 200, health.text
assert health.json().get('status') == 'ok', health.text

with (ROOT / 'fixtures' / 'insecure.yaml').open('rb') as manifest:
    response = client.post('/api/scans/manifests', files={'file': ('insecure.yaml', manifest, 'application/x-yaml')})
assert response.status_code == 200, response.text
scan = response.json()
assert scan.get('scan_id'), 'Missing scan ID'
assert isinstance(scan.get('nodes'), list) and scan['nodes'], 'Expected graph nodes'
assert isinstance(scan.get('edges'), list), 'Expected graph edges'
assert isinstance(scan.get('findings'), list), 'Expected findings'
assert isinstance(scan.get('security_assessments', []), list), 'Assessments must be a list'
assert client.get(f"/api/scans/{scan['scan_id']}").status_code == 200
assert client.get(f"/api/scans/{scan['scan_id']}/graph").status_code == 200
assert client.get(f"/api/scans/{scan['scan_id']}/findings").status_code == 200
print(f"CI smoke OK: {len(scan['nodes'])} nodes, {len(scan['edges'])} edges, {len(scan['findings'])} findings")
