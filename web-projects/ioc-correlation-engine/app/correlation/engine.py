"""Correlation engine — community detection, centrality analysis, campaign extraction."""

from __future__ import annotations

import logging

import community as community_louvain  # python-louvain
import networkx as nx

from app.models.enrichment import EnrichedIOC
from app.models.graph_models import (
    GraphEdge,
    GraphMetrics,
    GraphNode,
    GraphVisualization,
    IOCRelationship,
)
from config import settings

logger = logging.getLogger(__name__)


def detect_communities(G: nx.Graph) -> dict[str, int]:
    """Run Louvain community detection on the graph.

    Returns a mapping of node -> community_id.
    """
    if G.number_of_nodes() == 0:
        return {}

    if G.number_of_edges() == 0:
        # Each node is its own community
        return {node: i for i, node in enumerate(G.nodes())}

    partition = community_louvain.best_partition(
        G,
        weight="weight",
        resolution=settings.correlation.community_resolution,
    )
    n_communities = len(set(partition.values()))
    logger.info("Louvain detected %d communities", n_communities)
    return partition


def compute_centrality(G: nx.Graph) -> dict[str, float]:
    """Degree centrality — identifies infrastructure hubs."""
    if G.number_of_nodes() == 0:
        return {}
    return nx.degree_centrality(G)


def compute_graph_metrics(
    G: nx.Graph,
    centrality: dict[str, float],
) -> GraphMetrics:
    """Aggregate statistics about the correlation graph."""
    if G.number_of_nodes() == 0:
        return GraphMetrics(
            total_nodes=0,
            total_edges=0,
            connected_components=0,
            avg_degree=0.0,
            max_degree_node="N/A",
            max_degree_value=0,
            density=0.0,
            top_central_nodes=[],
        )

    degrees = dict(G.degree())
    max_node = max(degrees, key=degrees.get)

    top_central = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:10]

    return GraphMetrics(
        total_nodes=G.number_of_nodes(),
        total_edges=G.number_of_edges(),
        connected_components=nx.number_connected_components(G),
        avg_degree=round(sum(degrees.values()) / len(degrees), 2),
        max_degree_node=max_node,
        max_degree_value=degrees[max_node],
        density=round(nx.density(G), 4),
        top_central_nodes=[
            {"node": n, "centrality": round(c, 4)} for n, c in top_central
        ],
    )


def extract_relationships(G: nx.Graph) -> list[IOCRelationship]:
    """Flatten graph edges into serializable relationship objects."""
    relationships: list[IOCRelationship] = []
    for u, v, data in G.edges(data=True):
        for rel_type in data.get("relationship_types", set()):
            relationships.append(
                IOCRelationship(
                    source=u,
                    target=v,
                    relationship_type=rel_type,
                    weight=round(data["weight"], 3),
                    details="; ".join(data.get("details", [])),
                )
            )
    return relationships


def build_visualization(
    G: nx.Graph,
    partition: dict[str, int],
    enriched_iocs: list[EnrichedIOC],
) -> GraphVisualization:
    """Produce a D3/vis.js-compatible graph payload."""
    rep_lookup = {e.ioc.value: e.enrichment.reputation_score for e in enriched_iocs}
    type_lookup = {e.ioc.value: e.ioc.type.value for e in enriched_iocs}
    ts_lookup = {
        e.ioc.value: e.ioc.timestamp.isoformat() if e.ioc.timestamp else None
        for e in enriched_iocs
    }

    # Attribute weight table for picking the primary (strongest) rel type
    _type_strength = {
        "shared_ip": 6, "shared_malware_family": 5, "shared_c2_domain": 4,
        "shared_ssl_issuer": 3, "shared_asn": 2, "shared_hosting": 1,
        "time_proximity": 0,
    }

    nodes = [
        GraphNode(
            id=n,
            type=type_lookup.get(n, "unknown"),
            label=n,
            reputation=rep_lookup.get(n, 0),
            group=partition.get(n, 0),
            timestamp=ts_lookup.get(n),
        )
        for n in G.nodes()
    ]

    edges = []
    for u, v, d in G.edges(data=True):
        rel_types = d.get("relationship_types", set())
        # Pick the strongest relationship type as the primary label
        primary = max(rel_types, key=lambda t: _type_strength.get(t, 0)) if rel_types else "unknown"
        edges.append(GraphEdge(
            source=u,
            target=v,
            weight=round(d["weight"], 4),
            relationship_type=primary,
            label=", ".join(sorted(rel_types)),
        ))

    return GraphVisualization(nodes=nodes, edges=edges)
