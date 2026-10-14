from app.graph_layout import positions
from app.scanner import analyze

def test_positions_deterministic_and_complete():
    nodes=[{"id":"Pod/default/a"},{"id":"ServiceAccount/default/a"},{"id":"Role/default/r"}]
    edges=[{"source":nodes[0]["id"],"target":nodes[1]["id"],"relation":"uses_service_account"}]
    a=positions(nodes,edges)
    assert a == positions(nodes,edges)
    assert set(a)=={n["id"] for n in nodes}
    assert all(isinstance(v["x"],float) and isinstance(v["y"],float) for v in a.values())

def test_analysis_includes_layout():
    docs=[{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a","namespace":"demo"},"spec":{"containers":[{"name":"web","image":"nginx"}]}}]
    r=analyze(docs)
    assert set(r["graph_layout"])=={n["id"] for n in r["nodes"]}
