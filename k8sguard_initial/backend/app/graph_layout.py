"""Deterministic display geometry from real NetworkX resource relations."""
import networkx as nx


def positions(nodes, edges):
    """Return bounded positions, keyed by real node IDs (not synthetic visual nodes).

    Semantics-only annotation links are excluded from topology forces, but nodes
    remain visible. Coordinates are presentation metadata, not risk evidence.
    """
    g = nx.Graph()
    ids = [n["id"] for n in nodes]
    g.add_nodes_from(ids)
    for e in edges:
        if not e.get("semantic_only") and e["source"] in g and e["target"] in g:
            g.add_edge(e["source"], e["target"])
    if not ids:
        return {}
    components = sorted(nx.connected_components(g), key=lambda c: (-len(c), min(c)))
    output = {}
    offset = 0
    for group in components:
        sub = g.subgraph(group)
        if len(group) <= 90:
            xy = nx.spring_layout(sub, seed=42, iterations=45, scale=1)
            for node, pt in xy.items():
                output[node] = {"x": round(offset + 230 + float(pt[0])*175, 2), "y": round(235 + float(pt[1])*165, 2)}
        else:
            # Deterministic bounded-time fallback for very large components.
            for i, node in enumerate(sorted(group)):
                output[node] = {"x": offset + 100 + (i % 9)*185, "y": 80 + (i // 9)*105}
        offset += 520 if len(group) <= 90 else 1750
    return output
