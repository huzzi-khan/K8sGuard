# K8sGuard Hybrid Attack Graph — V6

This replaces the earlier V5 compressed world-layout implementation with three purpose-specific layouts and a camera that never shrinks every element automatically to fit an excessively tall graph.

## Views

- **Attack Path**: left-to-right layers; fixed spacing; selected candidate path prioritized when available.
- **Topology**: concentric rings for exploration; positions are deterministic from scanned graph relationships.
- **Namespaces**: separate namespace regions for high-level exploration.

**Filters**: search, namespace, Kubernetes resource type, relationship type, and severity (only nodes matched by existing findings). `Focused neighborhood` shows a connected subset; `Entire filtered inventory` retains full graph access. Edge labels can be enabled explicitly.

Interaction: node hover dims unrelated elements and opens a tooltip; click inspects resource, findings and relationships; drag a node to reposition; drag background to pan; wheel cursor-centred zoom; `Fit` for overview; `1:1` for a readable scale.

**Important**: Current view uses its own layout coordinates; NetworkX still performs analysis on backend and the original FastAPI graph, edges and attack paths remain authoritative. These visual coordinates do not modify backend scanner results. The `isSample` badge is preserved.

## Install

Copy the extracted project files over your current K8sGuard project, preserving `.git`, your virtual environment, Kubernetes credentials, and local configuration.

Backend: `cd backend && python -m pytest tests -q`
Frontend: `cd frontend && npm install && npm run build && npm run dev`

No frontend build was possible in the packaging runtime: npm registry DNS resolution returned `EAI_AGAIN`. JSX parsing with TypeScript compiler **passed** with zero syntax diagnostics; backend tests **53 passed**. These are not a substitute for browser verification.

## Acceptance checklist

- In Attack Path mode, the **Focused neighborhood** should show readable nodes and labels at the default zoom.
- Hover a node; related nodes/edges stay prominent and unrelated ones fade.
- Wheel zoom should stay around the cursor; `1:1` restores a readable view; `Fit` gives an overview, including very large graphs.
- Switch to Topology and Namespaces; both should have different, consistent visual layouts.
- Filter by namespace and type; counts should change. Clear filters should restore the display.
- Switch to Entire filtered inventory for all 500+ nodes. At this scale, inspect by zooming; no UI can make 500 labels legible simultaneously on a standard screen.
- Check sample fixture and a real YAML upload; live-scan 503 is a separate unresolved issue.

## Known limitations

This is a dependency-free React/SVG implementation, not a Cytoscape.js + ELK.js migration. True compound-graph layout and edge-crossing minimization on very large inventories would require an additional graph-layout engine and full browser integration testing. This is a robust iteration intended for presentation, but **visual quality has not yet been verified in the user's environment**.
