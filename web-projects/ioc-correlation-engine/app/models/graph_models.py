"""Graph-related response models."""

from __future__ import annotations

from pydantic import BaseModel

from app.models.campaign import Campaign


class IOCRelationship(BaseModel):
    """A single edge in the IOC relationship graph."""

    source: str
    target: str
    relationship_type: str  # e.g. "shared_asn", "shared_ip"
    weight: float
    details: str = ""


class GraphMetrics(BaseModel):
    """Aggregate statistics about the correlation graph."""

    total_nodes: int
    total_edges: int
    connected_components: int
    avg_degree: float
    max_degree_node: str
    max_degree_value: int
    density: float
    top_central_nodes: list[dict]  # [{node, centrality}, ...]


class GraphNode(BaseModel):
    id: str
    type: str
    label: str
    reputation: float = 0.0
    group: int = 0  # community id
    timestamp: str | None = None


class GraphEdge(BaseModel):
    source: str
    target: str
    weight: float
    relationship_type: str  # primary (strongest) relationship type
    label: str              # all types comma-joined


class GraphVisualization(BaseModel):
    """Payload optimized for D3 / vis.js rendering."""

    nodes: list[GraphNode]
    edges: list[GraphEdge]


class AnalysisResult(BaseModel):
    """Top-level response from the correlation pipeline."""

    campaigns: list[Campaign]
    graph_metrics: GraphMetrics
    analyst_summary: str
    ioc_relationships: list[IOCRelationship]
    graph_visualization: GraphVisualization
