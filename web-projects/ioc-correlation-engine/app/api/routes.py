"""FastAPI route definitions."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import PlainTextResponse, Response

from app.api.pipeline import run_analysis
from app.models.graph_models import AnalysisResult
from app.models.ioc import IOCBatchInput
from app.reporting.export import (
    campaigns_to_csv,
    iocs_to_csv,
    relationships_to_csv,
    to_json,
)
from app.services.ingestion import ingest_batch, ingest_text

logger = logging.getLogger(__name__)
router = APIRouter()

# In-memory store for the last analysis result (swap for Redis/DB in production)
_last_result: Optional[AnalysisResult] = None


def _store(result: AnalysisResult) -> AnalysisResult:
    global _last_result
    _last_result = result
    return result


# ──────────────────────────────────────────────────────────
# IOC Submission endpoints
# ──────────────────────────────────────────────────────────


@router.post("/api/v1/analyze", response_model=AnalysisResult, tags=["Analysis"])
async def analyze_iocs(batch: IOCBatchInput):
    """Submit a JSON array of IOCs and receive the full correlation analysis."""
    iocs = ingest_batch(batch)
    if not iocs:
        raise HTTPException(status_code=400, detail="No valid IOCs provided.")
    result = run_analysis(iocs)
    return _store(result)


@router.post("/api/v1/analyze/text", response_model=AnalysisResult, tags=["Analysis"])
async def analyze_text(body: dict):
    """Submit newline-separated IOC text for analysis.

    Body: ``{"text": "1.2.3.4\\nevil.com\\n<sha256>"}``
    """
    raw = body.get("text", "")
    if not raw.strip():
        raise HTTPException(status_code=400, detail="Empty text input.")
    iocs = ingest_text(raw)
    if not iocs:
        raise HTTPException(status_code=400, detail="No valid IOCs detected in input.")
    result = run_analysis(iocs)
    return _store(result)


@router.post("/api/v1/analyze/upload", response_model=AnalysisResult, tags=["Analysis"])
async def analyze_upload(file: UploadFile = File(...)):
    """Upload a JSON file containing an IOC batch."""
    import json

    content = await file.read()
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON file.")

    batch = IOCBatchInput(**data)
    iocs = ingest_batch(batch)
    if not iocs:
        raise HTTPException(status_code=400, detail="No valid IOCs in uploaded file.")
    result = run_analysis(iocs)
    return _store(result)


# ──────────────────────────────────────────────────────────
# Result retrieval / export
# ──────────────────────────────────────────────────────────


@router.get("/api/v1/result", response_model=AnalysisResult, tags=["Results"])
async def get_last_result():
    """Retrieve the most recent analysis result."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return _last_result


@router.get("/api/v1/result/summary", tags=["Results"])
async def get_summary():
    """Return just the analyst summary as plain text."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return PlainTextResponse(_last_result.analyst_summary)


@router.get("/api/v1/result/graph", tags=["Results"])
async def get_graph_visualization():
    """Return the graph visualization payload (nodes + edges) for D3/vis.js."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return _last_result.graph_visualization


# ──────────────────────────────────────────────────────────
# Export endpoints
# ──────────────────────────────────────────────────────────


@router.get("/api/v1/export/json", tags=["Export"])
async def export_json():
    """Download the full analysis as a JSON file."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return Response(
        content=to_json(_last_result),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=analysis_result.json"},
    )


@router.get("/api/v1/export/csv/campaigns", tags=["Export"])
async def export_campaigns_csv():
    """Download campaigns as CSV."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return Response(
        content=campaigns_to_csv(_last_result),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=campaigns.csv"},
    )


@router.get("/api/v1/export/csv/relationships", tags=["Export"])
async def export_relationships_csv():
    """Download IOC relationships as CSV."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return Response(
        content=relationships_to_csv(_last_result),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=relationships.csv"},
    )


@router.get("/api/v1/export/csv/iocs", tags=["Export"])
async def export_iocs_csv():
    """Download flat IOC list with campaign membership as CSV."""
    if _last_result is None:
        raise HTTPException(status_code=404, detail="No analysis has been run yet.")
    return Response(
        content=iocs_to_csv(_last_result),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=iocs.csv"},
    )
