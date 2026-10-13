from app.scanner import parse_manifests, analyze
from fastapi.testclient import TestClient
from app.main import app
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "insecure.yaml"

def test_fixture_rules():
    docs = parse_manifests(FIXTURE.read_bytes())
    result = analyze(docs)
    assert {x["rule"] for x in result["findings"]} >= {"RBAC_WILDCARD", "RBAC_SECRET_READ", "PRIVILEGED_CONTAINER"}
    assert result["nodes"] and result["edges"]

def test_invalid_document():
    try: parse_manifests(b"kind: Pod")
    except ValueError: pass
    else: assert False

def test_api():
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        with FIXTURE.open("rb") as f:
            result=client.post("/api/scans/manifests",files={"file":("insecure.yaml",f,"application/yaml")})
        assert result.status_code == 200
        sid=result.json()["scan_id"]
        assert client.get(f"/api/scans/{sid}/graph").status_code == 200
