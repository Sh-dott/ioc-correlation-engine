"""Builds a NetworkX graph from enriched IOCs.

Nodes  = IOC values
Edges  = Shared attributes (ASN, hosting provider, SSL issuer, associated
         IPs, malware family, C2 domains, time proximity).

Each edge carries a ``weight`` (0-1) and a ``relationship_type`` label.
"""

from __future__ import annotations

import logging
from datetime import datetime

import networkx as nx

from app.models.enrichment import (
    DomainEnrichment,
    EnrichedIOC,
    HashEnrichment,
    IPEnrichment,
)
from app.models.ioc import IOCType
from config import settings

logger = logging.getLogger(__name__)

# Attribute weights — how much each shared attribute contributes to edge weight.
# Values calibrated to reflect real-world correlation strength.
_ATTR_WEIGHTS: dict[str, float] = {
    "shared_ip": 0.85,              # Direct infrastructure overlap — very strong
    "shared_malware_family": 0.78,  # Same malware lineage — strong campaign signal
    "shared_c2_domain": 0.72,       # Same C&C — strong operational link
    "shared_ssl_issuer": 0.55,      # TLS cert overlap — moderate (can be legitimate)
    "shared_asn": 0.35,             # Same AS — weak-moderate (many IPs share an ASN)
    "shared_hosting": 0.30,         # Same hoster — weak (large shared-hosting providers)
    "time_proximity": 0.20,         # Temporal closeness — very weak alone (decayed below)
}


def build_graph(enriched_iocs: list[EnrichedIOC]) -> nx.Graph:
    """Construct the IOC relationship graph."""
    G = nx.Graph()

    # Add nodes
    for eioc in enriched_iocs:
        G.add_node(
            eioc.ioc.value,
            ioc_type=eioc.ioc.type.value,
            reputation=eioc.enrichment.reputation_score,
            source=eioc.ioc.source,
        )

    # Build lookup indexes for efficient pairwise comparison
    asn_map: dict[str, list[str]] = {}
    hosting_map: dict[str, list[str]] = {}
    ssl_map: dict[str, list[str]] = {}
    ip_map: dict[str, list[str]] = {}
    family_map: dict[str, list[str]] = {}
    c2_map: dict[str, list[str]] = {}

    for eioc in enriched_iocs:
        v = eioc.ioc.value
        e = eioc.enrichment

        if isinstance(e, IPEnrichment):
            asn_map.setdefault(e.asn, []).append(v)
            hosting_map.setdefault(e.hosting_provider, []).append(v)
            ip_map.setdefault(v, []).append(v)

        elif isinstance(e, DomainEnrichment):
            if e.ssl_issuer:
                ssl_map.setdefault(e.ssl_issuer, []).append(v)
            for ip in e.associated_ips:
                ip_map.setdefault(ip, []).append(v)

        elif isinstance(e, HashEnrichment):
            if e.malware_family:
                family_map.setdefault(e.malware_family, []).append(v)
            for c2 in e.known_c2_domains:
                c2_map.setdefault(c2, []).append(v)

    # Also cross-link: if a domain's associated IP equals an IP-type IOC
    ip_ioc_values = {
        eioc.ioc.value for eioc in enriched_iocs if eioc.ioc.type == IOCType.IP
    }
    for eioc in enriched_iocs:
        if isinstance(eioc.enrichment, DomainEnrichment):
            for assoc_ip in eioc.enrichment.associated_ips:
                if assoc_ip in ip_ioc_values:
                    _add_edge(G, eioc.ioc.value, assoc_ip,
                              "shared_ip", f"domain resolves to IOC IP {assoc_ip}")

    # Cross-link: if a hash's C2 domain matches a domain-type IOC
    domain_ioc_values = {
        eioc.ioc.value for eioc in enriched_iocs if eioc.ioc.type == IOCType.DOMAIN
    }
    for eioc in enriched_iocs:
        if isinstance(eioc.enrichment, HashEnrichment):
            for c2 in eioc.enrichment.known_c2_domains:
                if c2 in domain_ioc_values:
                    _add_edge(G, eioc.ioc.value, c2,
                              "shared_c2_domain", f"hash beacons to IOC domain {c2}")

    # Shared-attribute edges within groups
    _edges_from_group(G, asn_map, "shared_asn", "same ASN {}")
    _edges_from_group(G, hosting_map, "shared_hosting", "same hosting provider {}")
    _edges_from_group(G, ssl_map, "shared_ssl_issuer", "same SSL issuer {}")
    _edges_from_group(G, ip_map, "shared_ip", "shared IP {}")
    _edges_from_group(G, family_map, "shared_malware_family", "same malware family {}")
    _edges_from_group(G, c2_map, "shared_c2_domain", "shared C2 domain {}")

    # Time proximity edges
    _add_temporal_edges(G, enriched_iocs)

    logger.info(
        "Graph built: %d nodes, %d edges", G.number_of_nodes(), G.number_of_edges()
    )
    return G


# ---------- Internal helpers ----------


def _edges_from_group(
    G: nx.Graph,
    group_map: dict[str, list[str]],
    rel_type: str,
    detail_tpl: str,
) -> None:
    """Add edges between all IOCs that share the same attribute value."""
    for key, members in group_map.items():
        if len(members) < 2:
            continue
        for i in range(len(members)):
            for j in range(i + 1, len(members)):
                _add_edge(G, members[i], members[j], rel_type, detail_tpl.format(key))


def _add_edge(
    G: nx.Graph,
    u: str,
    v: str,
    rel_type: str,
    detail: str,
    weight_override: float | None = None,
) -> None:
    """Add or strengthen an edge between two nodes.

    Uses probability-union accumulation (diminishing returns) so multiple
    weak signals don't immediately saturate to 1.0.
    """
    if u == v:
        return
    if not G.has_node(u) or not G.has_node(v):
        return

    w = weight_override if weight_override is not None else _ATTR_WEIGHTS.get(rel_type, 0.2)

    if G.has_edge(u, v):
        data = G[u][v]
        # Probability union: P(A∪B) = 1 - (1-A)(1-B)  — diminishing returns
        data["weight"] = round(1.0 - (1.0 - data["weight"]) * (1.0 - w), 4)
        data["relationship_types"].add(rel_type)
        data["details"].append(detail)
    else:
        G.add_edge(
            u,
            v,
            weight=round(w, 4),
            relationship_types={rel_type},
            details=[detail],
        )


def _add_temporal_edges(G: nx.Graph, enriched_iocs: list[EnrichedIOC]) -> None:
    """Connect IOCs whose timestamps are within the configured proximity window.

    Weight decays linearly with time distance: closer in time → stronger signal.
    To avoid creating a complete graph from batch-submitted IOCs (all same
    timestamp), temporal edges are only added between pairs that already
    share at least one attribute-based edge.  This makes time proximity a
    *reinforcing* signal rather than a standalone connector.
    """
    threshold_hours = settings.correlation.time_proximity_hours
    base_weight = _ATTR_WEIGHTS["time_proximity"]
    items = [(eioc.ioc.value, eioc.ioc.timestamp) for eioc in enriched_iocs]

    for i in range(len(items)):
        for j in range(i + 1, len(items)):
            # Only reinforce existing attribute edges with temporal weight
            if not G.has_edge(items[i][0], items[j][0]):
                continue

            delta = abs((items[i][1] - items[j][1]).total_seconds()) / 3600
            if delta <= threshold_hours:
                # Decay: full weight at delta=0, zero at delta=threshold
                decay = 1.0 - (delta / threshold_hours) if threshold_hours > 0 else 1.0
                w = round(base_weight * decay, 4)
                if w < 0.02:
                    continue  # skip negligible correlations
                _add_edge(
                    G,
                    items[i][0],
                    items[j][0],
                    "time_proximity",
                    f"timestamps within {delta:.1f}h",
                    weight_override=w,
                )
