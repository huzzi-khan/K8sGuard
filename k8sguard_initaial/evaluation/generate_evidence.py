"""Reproducible, offline evaluation artifacts from bundled manifests.
Run from repository root: python evaluation/generate_evidence.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'backend'))
from app.scanner import analyze, parse_manifests

OUT = ROOT / 'evaluation' / 'results'
OUT.mkdir(parents=True, exist_ok=True)
rows = []
for manifest in sorted((ROOT / 'fixtures').glob('*.yaml')):
    docs = parse_manifests(manifest.read_bytes())
    result = analyze(docs)
    (OUT / (manifest.stem + '.json')).write_text(json.dumps(result, indent=2, default=str) + '\n', encoding='utf-8')
    row = {
        'fixture': manifest.name,
        'resources': result['resources'],
        'nodes': len(result['nodes']),
        'edges': len(result['edges']),
        'findings': len(result['findings']),
        'capability_paths': len(result['attack_paths']),
        'conditional_transitions': len(result['attack_transitions']),
        'operator_references': len(result['operator_references']),
        'cis_aligned_checks': len(result['cis_checks']),
    }
    rows.append(row)
summary = {'generated_at_utc': datetime.now(timezone.utc).isoformat(),
           'source': 'local deterministic bundled fixtures',
           'note': 'Counts describe detected results on these fixtures; they are NOT accuracy, coverage or Kubescape superiority metrics.',
           'fixtures': rows}
(OUT / 'summary.json').write_text(json.dumps(summary, indent=2)+'\n', encoding='utf-8')
print(json.dumps(summary, indent=2))
