"""Confidence scoring for campaign clusters.

The score is a weighted combination of four factors:
  1. Shared-attribute diversity — more relationship types = higher confidence
  2. Subgraph density — tightly connected clusters are more credible
  3. Central-node strength — presence of high-degree hubs increases confidence
  4. Aggregate reputation — higher average reputation of member IOCs
"""

from __future__ import annotations

import logging

import networkx as nx

from app.models.campaign import ConfidenceBreakdown
from config import settings

logger = logging.getLogger(__name__)

_cfg = settings.scoring


def compute_confidence(
    G: nx.Graph,
    cluster_nodes: list[str],
    centrality: dict[str, float],
) -> tuple[float, ConfidenceBreakdown]:
    """Return (score, breakdown) for a cluster of IOC nodes."""

    if len(cluster_nodes) < 2:
        breakdown = ConfidenceBreakdown(
            shared_attributes_score=0,
            graph_density_score=0,
            central_node_score=0,
            reputation_score=0,
            explanation="Single-node cluster — no correlation possible.",
        )
        return 0.0, breakdown

    subgraph = G.subgraph(cluster_nodes)

    # --- Factor 1: Shared-attribute diversity ---
    all_rel_types: set[str] = set()
    for _, _, data in subgraph.edges(data=True):
        all_rel_types.update(data.get("relationship_types", set()))

    # Normalize: 7 possible relationship types
    attr_score = min(len(all_rel_types) / 4.0, 1.0) * 100

    # --- Factor 2: Subgraph density ---
    density = nx.density(subgraph)
    density_score = density * 100

    # --- Factor 3: Central-node strength ---
    cluster_centralities = [centrality.get(n, 0) for n in cluster_nodes]
    max_centrality = max(cluster_centralities) if cluster_centralities else 0
    avg_centrality = (
        sum(cluster_centralities) / len(cluster_centralities)
        if cluster_centralities
        else 0
    )
    central_score = ((max_centrality * 0.6) + (avg_centrality * 0.4)) * 100
    central_score = min(central_score, 100)

    # --- Factor 4: Aggregate reputation ---
    reputations = [
        G.nodes[n].get("reputation", 50) for n in cluster_nodes
    ]
    avg_rep = sum(reputations) / len(reputations)
    rep_score = avg_rep  # already 0-100

    # --- Weighted combination ---
    score = (
        attr_score * _cfg.shared_attribute_weight
        + density_score * _cfg.graph_density_weight
        + central_score * _cfg.central_node_weight
        + rep_score * _cfg.reputation_weight
    )
    score = round(min(max(score, 0), 100), 1)

    explanation_parts = [
        f"Shared-attribute diversity: {len(all_rel_types)} relationship types detected "
        f"({', '.join(sorted(all_rel_types)) or 'none'}).",
        f"Subgraph density: {density:.3f} ({len(subgraph.edges())} edges across "
        f"{len(cluster_nodes)} nodes).",
        f"Central-node strength: max centrality {max_centrality:.3f}, "
        f"avg {avg_centrality:.3f}.",
        f"Aggregate reputation: avg score {avg_rep:.1f}/100.",
    ]

    breakdown = ConfidenceBreakdown(
        shared_attributes_score=round(attr_score, 1),
        graph_density_score=round(density_score, 1),
        central_node_score=round(central_score, 1),
        reputation_score=round(rep_score, 1),
        explanation=" ".join(explanation_parts),
    )

    logger.debug("Cluster %s -> confidence %.1f", cluster_nodes[:3], score)
    return score, breakdown
