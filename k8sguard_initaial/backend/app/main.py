import os
import uuid
from fastapi import Header
from .cluster_collect import collect_snapshot
from fastapi import FastAPI, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from .scanner import analyze, parse_manifests

app = FastAPI(title="K8sGuard API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"], allow_credentials=False,
                   allow_methods=["GET", "POST"], allow_headers=["*"])
scans: dict[str, dict] = {}

@app.get("/health")
def health():
    return {"status": "ok", "module": "A", "version": "0.1.0"}

@app.post("/api/scans/manifests")
async def upload_manifest(file: UploadFile = File(...)):
    content = await file.read(2*1024*1024+1)
    try:
        docs = parse_manifests(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    import uuid
    scan_id = str(uuid.uuid4())
    result = {"scan_id": scan_id, **analyze(docs)}
    scans[scan_id] = result
    return result

@app.get("/api/scans/{scan_id}")
def get_scan(scan_id: str):
    if scan_id not in scans: raise HTTPException(404, "Scan not found")
    return scans[scan_id]

@app.get("/api/scans/{scan_id}/findings")
def get_findings(scan_id: str):
    return get_scan(scan_id)["findings"]

@app.get("/api/scans/{scan_id}/graph")
def get_graph(scan_id: str):
    s = get_scan(scan_id)
    return {"nodes": s["nodes"], "edges": s["edges"]}

@app.post("/api/scans/live")
def scan_live_cluster(x_local_scan_token: str | None = Header(default=None)):
    expected_token = os.environ.get("K8SGUARD_LOCAL_SCAN_TOKEN")
    context = os.environ.get("K8SGUARD_CONTEXT")

    if not expected_token or x_local_scan_token != expected_token:
        raise HTTPException(
            status_code=403,
            detail="Live scanning is not authorized"
        )

    if not context:
        raise HTTPException(
            status_code=503,
            detail="K8SGUARD_CONTEXT is not configured"
        )

    try:
        resources, errors = collect_snapshot(context=context)
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Kubernetes collection failed. Check server logs."
        )

    if not resources:
        raise HTTPException(
            status_code=503,
            detail="No Kubernetes resources were collected"
        )

    if len(resources) > 10000:
        raise HTTPException(
            status_code=413,
            detail="Cluster snapshot exceeds safety limit"
        )

    scan_id = str(uuid.uuid4())

    result = {
        "scan_id": scan_id,
        **analyze(resources),
        "source": "live_cluster",
        "cluster_context": context,
        "collection_errors": errors,
    }

    scans[scan_id] = result

    return result
