# K8sGuard V5 — spacious graph and centred viewport

The previous graph compressed all computed node coordinates into the visible 610px viewport, which caused collisions and made the graph jump toward an edge during zoom. V5 removes that normalization and uses a graph-sized **world coordinate system**.

- Connected components occupy separate vertical lanes.
- Connected resources receive breadth-first layers with 310px horizontal and 150px vertical spacing; large layers wrap into readable rows.
- The SVG viewport **fits the world bounding box around its centre**. Zoom and pan preserve this centre rather than scaling around (0,0).
- SVG links and nodes use the exact same transformation; node dragging performs inverse camera-coordinate mapping.
- Focus view and full-inventory view remain available. Nothing is discarded from scan results.
- Existing shapes, legend, hover tooltip, connected-node highlighting, and evidence inspector remain intact.

## Verification

Run `cd frontend && npm install && npm run build && npm run dev` in WSL. Dependencies are not available in this container; production build and browser operation have not been verified here. Inspect both focused and full inventory, zoom in several steps, drag a node, pan, reset, and hover connections. Backend code unchanged.

For 500+ resource graphs, start in focused view and zoom into full inventory when required. The full inventory is still a very large topology and cannot be legible in one static 610px overview without changing scale.
