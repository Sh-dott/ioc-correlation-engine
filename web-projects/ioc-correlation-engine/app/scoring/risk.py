"""Risk-level assignment and campaign assembly."""

from __future__ import annotations

import logging
from collections import defaultdict

import networkx as nx

from app.models.campaign import Campaign, MitreMapping, RiskLevel
from app.models.enrichment import (
    DomainEnrichment,
    EnrichedIOC,
    HashEnrichment,
    IPEnrichment,
)
from app.scoring.confidence import compute_confidence
from config import settings

logger = logging.getLogger(__name__)


def classify_risk(confidence: float) -> RiskLevel:
    """Map a confidence score to a risk level."""
    cfg = settings.scoring
    if confidence >= cfg.critical_threshold:
        return RiskLevel.CRITICAL
    if confidence >= cfg.high_threshold:
        return RiskLevel.HIGH
    if confidence >= cfg.medium_threshold:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


# ---------- Mock MITRE ATT&CK mappings ----------

_MITRE_BY_FAMILY: dict[str, list[MitreMapping]] = {
    "Cobalt Strike": [
        MitreMapping(tactic="Command and Control", technique_id="T1071.001",
                     technique_name="Application Layer Protocol: Web Protocols"),
        MitreMapping(tactic="Execution", technique_id="T1059.001",
                     technique_name="Command and Scripting Interpreter: PowerShell"),
    ],
    "Emotet": [
        MitreMapping(tactic="Initial Access", technique_id="T1566.001",
                     technique_name="Phishing: Spearphishing Attachment"),
        MitreMapping(tactic="Execution", technique_id="T1204.002",
                     technique_name="User Execution: Malicious File"),
    ],
    "TrickBot": [
        MitreMapping(tactic="Credential Access", technique_id="T1555.003",
                     technique_name="Credentials from Password Stores: Web Browsers"),
        MitreMapping(tactic="Discovery", technique_id="T1018",
                     technique_name="Remote System Discovery"),
    ],
    "QakBot": [
        MitreMapping(tactic="Initial Access", technique_id="T1566.002",
                     technique_name="Phishing: Spearphishing Link"),
        MitreMapping(tactic="Defense Evasion", technique_id="T1055",
                     technique_name="Process Injection"),
    ],
    "AsyncRAT": [
        MitreMapping(tactic="Command and Control", technique_id="T1095",
                     technique_name="Non-Application Layer Protocol"),
        MitreMapping(tactic="Collection", technique_id="T1113",
                     technique_name="Screen Capture"),
    ],
}

_DEFAULT_MITRE = [
    MitreMapping(tactic="Command and Control", technique_id="T1071",
                 technique_name="Application Layer Protocol"),
]


def build_campaigns(
    G: nx.Graph,
    partition: dict[str, int],
    centrality: dict[str, float],
    enriched_iocs: list[EnrichedIOC],
) -> list[Campaign]:
    """Group correlated clusters into Campaign objects."""

    # Group nodes by community
    communities: dict[int, list[str]] = defaultdict(list)
    for node, comm_id in partition.items():
        communities[comm_id].append(node)

    # Enrichment lookup
    enrichment_lookup = {e.ioc.value: e for e in enriched_iocs}

    campaigns: list[Campaign] = []

    for idx, (comm_id, members) in enumerate(
        sorted(communities.items(), key=lambda x: -len(x[1]))
    ):
        if len(members) < 2:
            # Singletons are not actionable campaigns
            continue

        campaign_id = f"CAMP-{idx + 1:03d}"
        confidence, breakdown = compute_confidence(G, members, centrality)
        risk = classify_risk(confidence)

        core_infra = _extract_core_infrastructure(members, enrichment_lookup)
        mitre = _collect_mitre(members, enrichment_lookup)
        name = _generate_campaign_name(core_infra, members, enrichment_lookup)

        campaigns.append(
            Campaign(
                campaign_id=campaign_id,
                name=name,
                ioc_count=len(members),
                ioc_values=sorted(members),
                core_infrastructure=core_infra,
                confidence_score=confidence,
                confidence_breakdown=breakdown,
                risk_level=risk,
                mitre_mappings=mitre,
            )
        )

    campaigns.sort(key=lambda c: -c.confidence_score)
    logger.info("Assembled %d campaigns from %d communities", len(campaigns), len(communities))
    return campaigns


def _extract_core_infrastructure(
    members: list[str],
    lookup: dict[str, EnrichedIOC],
) -> list[str]:
    """Identify the shared infrastructure that binds the cluster."""
    infra: set[str] = set()

    for m in members:
        eioc = lookup.get(m)
        if not eioc:
            continue
        e = eioc.enrichment
        if isinstance(e, IPEnrichment):
            infra.add(e.asn)
            infra.add(e.hosting_provider)
        elif isinstance(e, DomainEnrichment):
            if e.ssl_issuer:
                infra.add(f"SSL:{e.ssl_issuer}")
            infra.add(f"Registrar:{e.registrar}")
        elif isinstance(e, HashEnrichment):
            if e.malware_family:
                infra.add(f"Family:{e.malware_family}")

    return sorted(infra)


def _collect_mitre(
    members: list[str],
    lookup: dict[str, EnrichedIOC],
) -> list[MitreMapping]:
    """Gather MITRE ATT&CK mappings from malware families in the cluster."""
    seen: set[str] = set()
    mappings: list[MitreMapping] = []

    for m in members:
        eioc = lookup.get(m)
        if not eioc:
            continue
        if isinstance(eioc.enrichment, HashEnrichment) and eioc.enrichment.malware_family:
            family = eioc.enrichment.malware_family
            for mm in _MITRE_BY_FAMILY.get(family, _DEFAULT_MITRE):
                if mm.technique_id not in seen:
                    seen.add(mm.technique_id)
                    mappings.append(mm)

    return mappings


def _generate_campaign_name(
    core_infra: list[str],
    members: list[str],
    lookup: dict[str, EnrichedIOC],
) -> str:
    """Create a human-readable campaign label."""
    # Try to name after the malware family if one exists
    for m in members:
        eioc = lookup.get(m)
        if eioc and isinstance(eioc.enrichment, HashEnrichment):
            if eioc.enrichment.malware_family:
                return f"{eioc.enrichment.malware_family} Infrastructure Cluster"

    # Fall back to hosting/ASN
    for infra in core_infra:
        if infra.startswith("AS"):
            return f"{infra} Hosting Cluster"

    return f"Threat Cluster ({len(members)} indicators)"
