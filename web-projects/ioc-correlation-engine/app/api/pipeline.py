"""End-to-end analysis pipeline.

Orchestrates: ingestion → enrichment → graph → correlation → scoring → reporting.
"""

from __future__ import annotations

import logging

from app.correlation.engine import (
    build_visualization,
    compute_centrality,
    compute_graph_metrics,
    detect_communities,
    extract_relationships,
)
from app.correlation.graph_builder import build_graph
from app.models.graph_models import AnalysisResult
from app.models.ioc import IOC
from app.reporting.summary import generate_summary
from app.scoring.risk import build_campaigns
from app.services.enrichment import enrich_batch

logger = logging.getLogger(__name__)


def run_analysis(iocs: list[IOC]) -> AnalysisResult:
    """Execute the full correlation pipeline and return the analysis result."""

    logger.info("Pipeline started with %d IOCs", len(iocs))

    # 1. Enrich
    enriched = enrich_batch(iocs)
    logger.info("Enrichment complete")

    # 2. Build relationship graph
    graph = build_graph(enriched)
    logger.info("Graph built: %d nodes, %d edges",
                graph.number_of_nodes(), graph.number_of_edges())

    # 3. Community detection + centrality
    partition = detect_communities(graph)
    centrality = compute_centrality(graph)

    # 4. Graph metrics
    metrics = compute_graph_metrics(graph, centrality)

    # 5. Campaign assembly
    campaigns = build_campaigns(graph, partition, centrality, enriched)
    logger.info("Identified %d campaigns", len(campaigns))

    # 6. Extract serializable relationships
    relationships = extract_relationships(graph)

    # 7. Visualization payload
    viz = build_visualization(graph, partition, enriched)

    # 8. Analyst summary
    summary = generate_summary(campaigns, metrics, relationships, len(iocs))

    return AnalysisResult(
        campaigns=campaigns,
        graph_metrics=metrics,
        analyst_summary=summary,
        ioc_relationships=relationships,
        graph_visualization=viz,
    )
