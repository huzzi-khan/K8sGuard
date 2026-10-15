# Increment 8 — Frontend explainability

Cumulative project based on Increment 7. No backend behavior was altered.

- Evidence inspector now displays configuration facts, risk interpretation, unverified prerequisites, permission grant details, and clearly provisional MITRE/CIS references.
- Conditional transition details expose the backend `explainability`, `preconditions`, and `credential_evidence` fields.
- Clicking a referenced resource in a selected candidate path opens its node inspector.
- Assessment navigation centres the graph camera on the affected element after switching to topology/full inventory.
- Risk and review arrowheads reflect edge classifications.

**Limitations:** Generic graph assessments do not yet have specific machine-verifiable exploit preconditions; the inspector explicitly identifies those as unverified rather than inventing evidence. No primary-edition CIS v2.1.0 mappings are claimed verified. The visual interaction requires browser validation with real scan results.
