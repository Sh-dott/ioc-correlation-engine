"""Application configuration."""

from pydantic import BaseModel


class CorrelationConfig(BaseModel):
    """Thresholds and weights for the correlation engine."""

    # Time proximity: IOCs within this window (hours) get a temporal edge
    time_proximity_hours: float = 48.0

    # Minimum edge weight to keep in the graph
    min_edge_weight: float = 0.1

    # Louvain community detection resolution (higher = more granular clusters)
    community_resolution: float = 1.0


class ScoringConfig(BaseModel):
    """Weights used to compute campaign confidence scores."""

    shared_attribute_weight: float = 0.30
    graph_density_weight: float = 0.20
    central_node_weight: float = 0.25
    reputation_weight: float = 0.25

    # Risk-level thresholds (confidence score)
    critical_threshold: int = 85
    high_threshold: int = 65
    medium_threshold: int = 40


class AppConfig(BaseModel):
    """Top-level application settings."""

    app_name: str = "IOC Correlation Engine"
    version: str = "1.0.0"
    debug: bool = False
    correlation: CorrelationConfig = CorrelationConfig()
    scoring: ScoringConfig = ScoringConfig()


settings = AppConfig()
