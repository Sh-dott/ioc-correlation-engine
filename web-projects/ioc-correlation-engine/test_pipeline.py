"""Quick smoke test — run the full pipeline against sample data."""

import json
import sys
import os

os.environ.setdefault("PYTHONIOENCODING", "utf-8")
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")

from app.api.pipeline import run_analysis
from app.services.ingestion import ingest_batch
from app.models.ioc import IOCBatchInput

with open("sample_iocs.json") as f:
    data = json.load(f)

batch = IOCBatchInput(**data)
iocs = ingest_batch(batch)
print(f"Ingested {len(iocs)} IOCs")

result = run_analysis(iocs)

print(f"\n=== CAMPAIGNS ({len(result.campaigns)}) ===")
for c in result.campaigns:
    print(f"  {c.campaign_id}: {c.name} | IOCs: {c.ioc_count} | "
          f"Confidence: {c.confidence_score} | Risk: {c.risk_level.value}")

print(f"\n=== GRAPH METRICS ===")
m = result.graph_metrics
print(f"  Nodes: {m.total_nodes}, Edges: {m.total_edges}, "
      f"Components: {m.connected_components}, Density: {m.density}")
print(f"  Hub: {m.max_degree_node} (degree {m.max_degree_value})")

print(f"\n=== RELATIONSHIPS ({len(result.ioc_relationships)}) ===")
for r in result.ioc_relationships[:10]:
    print(f"  {r.source[:30]:30s} <-> {r.target[:30]:30s} [{r.relationship_type}] w={r.weight}")

print("\n=== ANALYST SUMMARY (first 80 lines) ===")
for line in result.analyst_summary.split("\n")[:80]:
    print(line)

print("\n\n[OK] Pipeline completed successfully.")
