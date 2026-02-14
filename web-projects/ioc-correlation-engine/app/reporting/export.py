"""Export utilities — JSON and CSV formatters."""

from __future__ import annotations

import csv
import io
import json

from app.models.graph_models import AnalysisResult


def to_json(result: AnalysisResult) -> str:
    """Serialize the full analysis result to indented JSON."""
    return result.model_dump_json(indent=2)


def campaigns_to_csv(result: AnalysisResult) -> str:
    """Export campaigns as a CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "campaign_id",
        "name",
        "ioc_count",
        "confidence_score",
        "risk_level",
        "core_infrastructure",
        "ioc_values",
    ])
    for c in result.campaigns:
        writer.writerow([
            c.campaign_id,
            c.name,
            c.ioc_count,
            c.confidence_score,
            c.risk_level.value,
            "; ".join(c.core_infrastructure),
            "; ".join(c.ioc_values),
        ])
    return buf.getvalue()


def relationships_to_csv(result: AnalysisResult) -> str:
    """Export IOC relationships as a CSV string."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["source", "target", "relationship_type", "weight", "details"])
    for r in result.ioc_relationships:
        writer.writerow([r.source, r.target, r.relationship_type, r.weight, r.details])
    return buf.getvalue()


def iocs_to_csv(result: AnalysisResult) -> str:
    """Flat list of all IOCs across all campaigns."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["ioc_value", "campaign_id", "campaign_name", "risk_level"])
    for c in result.campaigns:
        for ioc_val in c.ioc_values:
            writer.writerow([ioc_val, c.campaign_id, c.name, c.risk_level.value])
    return buf.getvalue()
