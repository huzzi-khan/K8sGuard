# Increment 4 — Risk-aware graph inspector

- Connects graph_assessments and permission_grants supplied by Increment 3 to clickable graph nodes/edges.
- Shows supporting permission grant records, MITRE technique annotations, candidate CIS mappings and raw evidence.
- Colors rule-supported risk edges red and review edges amber. This is not a claim of exploitation.
- Groups duplicate candidate capability and CIS check rows and provides graph navigation from assessments.
- Maintains backend API and existing tests.

Caveats: local visual validation is required; benchmark mappings still await primary-edition verification. Only assessed edges are colored red. Other edges are not certified secure.
