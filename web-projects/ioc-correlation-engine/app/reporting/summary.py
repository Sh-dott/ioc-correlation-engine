"""Analyst-ready intelligence summary generation.

Produces structured CTI reports using deterministic templates —
no LLM required, reads like a real threat intelligence brief.
"""

from __future__ import annotations

import textwrap
from datetime import datetime

from app.models.campaign import Campaign, RiskLevel
from app.models.graph_models import GraphMetrics, IOCRelationship


def generate_summary(
    campaigns: list[Campaign],
    metrics: GraphMetrics,
    relationships: list[IOCRelationship],
    total_iocs: int,
) -> str:
    """Generate the full analyst intelligence summary."""
    sections = [
        _header(),
        _executive_summary(campaigns, metrics, total_iocs),
        _campaign_overview(campaigns),
        _key_infrastructure(campaigns),
        _primary_indicators(campaigns),
        _confidence_assessment(campaigns),
        _mitre_section(campaigns),
        _recommended_actions(campaigns),
        _footer(),
    ]
    return "\n".join(sections)


# ---------- Section builders ----------


def _header() -> str:
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    return textwrap.dedent(f"""\
        ╔══════════════════════════════════════════════════════════════╗
        ║            THREAT INTELLIGENCE CORRELATION REPORT           ║
        ║                IOC Correlation Engine v1.0                  ║
        ╚══════════════════════════════════════════════════════════════╝

        Report Generated: {now}
        Classification:   TLP:AMBER
        ──────────────────────────────────────────────────────────────""")


def _executive_summary(
    campaigns: list[Campaign],
    metrics: GraphMetrics,
    total_iocs: int,
) -> str:
    critical = sum(1 for c in campaigns if c.risk_level == RiskLevel.CRITICAL)
    high = sum(1 for c in campaigns if c.risk_level == RiskLevel.HIGH)
    medium = sum(1 for c in campaigns if c.risk_level == RiskLevel.MEDIUM)
    low = sum(1 for c in campaigns if c.risk_level == RiskLevel.LOW)

    severity_word = "critical" if critical else "significant" if high else "moderate"

    lines = [
        "",
        "1. EXECUTIVE SUMMARY",
        "─" * 60,
        "",
        f"Analysis of {total_iocs} indicators of compromise identified "
        f"{len(campaigns)} distinct threat campaign(s) with {severity_word} "
        f"correlation confidence.",
        "",
        f"  • Campaigns identified : {len(campaigns)}",
        f"  • CRITICAL risk        : {critical}",
        f"  • HIGH risk            : {high}",
        f"  • MEDIUM risk          : {medium}",
        f"  • LOW risk             : {low}",
        "",
        f"  • IOC graph nodes      : {metrics.total_nodes}",
        f"  • IOC graph edges      : {metrics.total_edges}",
        f"  • Connected components : {metrics.connected_components}",
        f"  • Graph density        : {metrics.density}",
        "",
    ]

    if critical or high:
        lines.append(
            "  ⚠  IMMEDIATE ACTION RECOMMENDED — high-confidence threat clusters "
            "detected. See Recommended Actions."
        )
        lines.append("")

    return "\n".join(lines)


def _campaign_overview(campaigns: list[Campaign]) -> str:
    lines = [
        "2. CAMPAIGN OVERVIEW",
        "─" * 60,
        "",
    ]
    if not campaigns:
        lines.append("  No multi-indicator campaigns were identified.")
        lines.append("")
        return "\n".join(lines)

    for c in campaigns:
        lines.extend([
            f"  ┌─ {c.campaign_id}: {c.name}",
            f"  │  IOCs            : {c.ioc_count}",
            f"  │  Confidence      : {c.confidence_score:.1f}/100",
            f"  │  Risk Level      : {c.risk_level.value}",
            f"  │  Core Infra      : {', '.join(c.core_infrastructure[:5]) or 'N/A'}",
            f"  └{'─' * 55}",
            "",
        ])
    return "\n".join(lines)


def _key_infrastructure(campaigns: list[Campaign]) -> str:
    lines = [
        "3. KEY INFRASTRUCTURE",
        "─" * 60,
        "",
    ]

    all_infra: dict[str, int] = {}
    for c in campaigns:
        for infra in c.core_infrastructure:
            all_infra[infra] = all_infra.get(infra, 0) + 1

    if not all_infra:
        lines.append("  No shared infrastructure identified.")
        lines.append("")
        return "\n".join(lines)

    for infra, count in sorted(all_infra.items(), key=lambda x: -x[1]):
        bar = "█" * min(count * 3, 30)
        lines.append(f"  {infra:<40s} [{count}x] {bar}")

    lines.append("")
    return "\n".join(lines)


def _primary_indicators(campaigns: list[Campaign]) -> str:
    lines = [
        "4. PRIMARY INDICATORS",
        "─" * 60,
        "",
    ]

    for c in campaigns:
        lines.append(f"  {c.campaign_id} — {c.name}:")
        for ioc_val in c.ioc_values[:10]:
            lines.append(f"    • {ioc_val}")
        if c.ioc_count > 10:
            lines.append(f"    ... and {c.ioc_count - 10} more")
        lines.append("")

    return "\n".join(lines)


def _confidence_assessment(campaigns: list[Campaign]) -> str:
    lines = [
        "5. CONFIDENCE ASSESSMENT",
        "─" * 60,
        "",
    ]

    for c in campaigns:
        lines.append(f"  {c.campaign_id} — Confidence: {c.confidence_score:.1f}/100")
        if c.confidence_breakdown:
            bd = c.confidence_breakdown
            lines.extend([
                f"    Shared attributes  : {bd.shared_attributes_score:.1f}/100",
                f"    Graph density      : {bd.graph_density_score:.1f}/100",
                f"    Central-node score : {bd.central_node_score:.1f}/100",
                f"    Reputation score   : {bd.reputation_score:.1f}/100",
                f"    Assessment         : {bd.explanation}",
            ])
        lines.append("")

    return "\n".join(lines)


def _mitre_section(campaigns: list[Campaign]) -> str:
    lines = [
        "6. MITRE ATT&CK MAPPING",
        "─" * 60,
        "",
    ]

    any_mitre = False
    for c in campaigns:
        if c.mitre_mappings:
            any_mitre = True
            lines.append(f"  {c.campaign_id} — {c.name}:")
            for m in c.mitre_mappings:
                lines.append(f"    [{m.technique_id}] {m.technique_name} ({m.tactic})")
            lines.append("")

    if not any_mitre:
        lines.append("  No MITRE ATT&CK techniques mapped for current indicators.")
        lines.append("")

    return "\n".join(lines)


def _recommended_actions(campaigns: list[Campaign]) -> str:
    lines = [
        "7. RECOMMENDED ACTIONS",
        "─" * 60,
        "",
    ]

    critical_campaigns = [c for c in campaigns if c.risk_level == RiskLevel.CRITICAL]
    high_campaigns = [c for c in campaigns if c.risk_level == RiskLevel.HIGH]
    other_campaigns = [c for c in campaigns
                       if c.risk_level not in (RiskLevel.CRITICAL, RiskLevel.HIGH)]

    if critical_campaigns:
        lines.append("  IMMEDIATE (CRITICAL):")
        lines.extend([
            "    1. Block all identified IOCs at network perimeter (firewall, proxy, DNS sinkhole).",
            "    2. Initiate incident response triage for any internal hosts communicating",
            "       with campaign infrastructure.",
            "    3. Conduct retroactive log search across SIEM for historical contact",
            "       with identified indicators (minimum 90-day lookback).",
            "    4. Escalate to SOC Tier-3 / Threat Hunt team for deep-dive investigation.",
            "",
        ])

    if high_campaigns:
        lines.append("  HIGH PRIORITY:")
        lines.extend([
            "    1. Add all campaign IOCs to detection rules (IDS/IPS, EDR).",
            "    2. Enrich internal telemetry against identified infrastructure (ASN, hosting).",
            "    3. Review email gateway logs for inbound messages referencing campaign domains.",
            "    4. Update threat intelligence platform with correlated campaign data.",
            "",
        ])

    if other_campaigns:
        lines.append("  MONITORING:")
        lines.extend([
            "    1. Add indicators to watchlists for passive monitoring.",
            "    2. Schedule periodic re-analysis as new IOCs are ingested.",
            "    3. Cross-reference with external CTI feeds for additional context.",
            "",
        ])

    if not campaigns:
        lines.extend([
            "  No actionable campaigns detected. Continue routine monitoring.",
            "  Consider re-analysis with additional indicators for broader correlation.",
            "",
        ])

    return "\n".join(lines)


def _footer() -> str:
    return textwrap.dedent("""\
        ──────────────────────────────────────────────────────────────
        END OF REPORT
        Generated by IOC Correlation Engine v1.0
        ══════════════════════════════════════════════════════════════""")
