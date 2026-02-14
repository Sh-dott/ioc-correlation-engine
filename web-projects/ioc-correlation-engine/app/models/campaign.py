"""Campaign and risk models."""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ConfidenceBreakdown(BaseModel):
    """Explains how the confidence score was calculated."""

    shared_attributes_score: float
    graph_density_score: float
    central_node_score: float
    reputation_score: float
    explanation: str


class MitreMapping(BaseModel):
    """Mock MITRE ATT&CK mapping."""

    tactic: str
    technique_id: str
    technique_name: str


class Campaign(BaseModel):
    """A cluster of correlated IOCs grouped as a potential campaign."""

    campaign_id: str
    name: str
    ioc_count: int
    ioc_values: list[str]
    core_infrastructure: list[str]
    confidence_score: float  # 0-100
    confidence_breakdown: Optional[ConfidenceBreakdown] = None
    risk_level: RiskLevel
    mitre_mappings: list[MitreMapping] = []
    summary: str = ""
