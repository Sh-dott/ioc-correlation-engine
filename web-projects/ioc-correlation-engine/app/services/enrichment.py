"""Deterministic mock enrichment layer.

Every enrichment result is derived from a stable hash of the IOC value,
so the same IOC always produces the same enrichment — making the system
reproducible and testable without external API calls.
"""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta

from app.models.enrichment import (
    DomainEnrichment,
    EnrichedIOC,
    HashEnrichment,
    IPEnrichment,
)
from app.models.ioc import IOC, IOCType

logger = logging.getLogger(__name__)

# ---------- Reference data for deterministic generation ----------

_COUNTRIES = [
    "US", "RU", "CN", "DE", "NL", "UA", "RO", "KR", "IR", "BR",
    "GB", "FR", "JP", "IN", "SG",
]

_HOSTING_PROVIDERS = [
    "DigitalOcean", "OVH", "Hetzner", "Bulletproof-Host-X",
    "CloudFlare", "Leaseweb",
]

_REGISTRARS = [
    "Namecheap", "GoDaddy", "Tucows", "PDR Ltd", "Eranet",
    "PublicDomainRegistry", "NameSilo", "Epik", "Dynadot", "Gandi",
]

_SSL_ISSUERS = [
    "Let's Encrypt", "Comodo", "DigiCert",
    "Self-Signed", None,
]

_MALWARE_FAMILIES = [
    "Cobalt Strike", "Emotet", "TrickBot", "QakBot", "IcedID",
    "AsyncRAT", "RedLine", "Raccoon", "AgentTesla", "Remcos",
    None,
]

_FILE_TYPES = [
    "PE32 executable", "PE32+ executable", "ELF 64-bit",
    "Mach-O 64-bit", "PDF document", "Microsoft Word",
    "ZIP archive", "DLL", "JavaScript", "Python script",
]

_DETECTION_NAMES = [
    "Trojan.GenericKD", "Backdoor.Agent", "Ransom.Win32",
    "Exploit.CVE-2024", "HackTool.Mimikatz", "Worm.Generic",
]

_MOCK_DOMAINS = [
    "update-service.xyz", "cdn-static.top", "api-gateway.cc",
    "mail-secure.info", "cloud-sync.ru", "data-transfer.cn",
    "login-portal.tk", "dl-content.pw",
]


def _stable_int(value: str, salt: str = "") -> int:
    """Return a deterministic integer from an IOC value."""
    digest = hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()
    return int(digest[:8], 16)


def _pick(options: list, value: str, salt: str = ""):
    n = _stable_int(value, salt)
    return options[n % len(options)]


def _reputation(value: str) -> float:
    """Score 0-100 derived from the IOC value. Higher = more malicious."""
    n = _stable_int(value, "rep")
    base = (n % 80) + 10  # 10-89
    # Bias toward higher scores for more "interesting" results
    return round(min(base * 1.1, 100.0), 1)


# ---------- Public API ----------


def enrich_ioc(ioc: IOC) -> EnrichedIOC:
    """Enrich a single IOC and return the combined object."""
    logger.debug("Enriching %s (%s)", ioc.value, ioc.type.value)

    if ioc.type == IOCType.IP:
        enrichment = _enrich_ip(ioc.value)
    elif ioc.type == IOCType.DOMAIN:
        enrichment = _enrich_domain(ioc.value)
    elif ioc.type == IOCType.HASH:
        enrichment = _enrich_hash(ioc.value)
    else:
        raise ValueError(f"Unsupported IOC type: {ioc.type}")

    return EnrichedIOC(ioc=ioc, enrichment=enrichment)


def enrich_batch(iocs: list[IOC]) -> list[EnrichedIOC]:
    """Enrich a list of IOCs."""
    enriched = [enrich_ioc(ioc) for ioc in iocs]
    logger.info("Enriched %d IOCs", len(enriched))
    return enriched


# ---------- Type-specific enrichment ----------


def _enrich_ip(value: str) -> IPEnrichment:
    n = _stable_int(value)
    # Small ASN pool (8 values) so IPs realistically share ASNs
    _ASN_POOL = [13335, 16276, 24940, 14061, 20473, 63949, 18245, 9009]
    asn_number = _ASN_POOL[n % len(_ASN_POOL)]

    common_ports = [22, 80, 443, 8080, 8443, 3389, 445, 53, 25, 4444, 9090]
    port_count = (n % 4) + 1
    open_ports = sorted(
        set(common_ports[(_stable_int(value, f"port{i}")) % len(common_ports)]
            for i in range(port_count))
    )

    return IPEnrichment(
        asn=f"AS{asn_number}",
        country=_pick(_COUNTRIES, value, "country"),
        hosting_provider=_pick(_HOSTING_PROVIDERS, value, "host"),
        open_ports=open_ports,
        reputation_score=_reputation(value),
        abuse_contacts=[f"abuse@as{asn_number}.net"],
    )


def _enrich_domain(value: str) -> DomainEnrichment:
    n = _stable_int(value)

    # Create deterministic associated IPs (1-3)
    ip_count = (n % 3) + 1
    associated_ips = []
    for i in range(ip_count):
        seed = _stable_int(value, f"assoc_ip_{i}")
        ip = f"{(seed >> 24) & 0xFF}.{(seed >> 16) & 0xFF}.{(seed >> 8) & 0xFF}.{seed & 0xFF}"
        associated_ips.append(ip)

    # Creation date: 30-1800 days in the past
    days_ago = (n % 1770) + 30
    creation_date = datetime.utcnow() - timedelta(days=days_ago)

    return DomainEnrichment(
        creation_date=creation_date,
        registrar=_pick(_REGISTRARS, value, "registrar"),
        ssl_issuer=_pick(_SSL_ISSUERS, value, "ssl"),
        associated_ips=associated_ips,
        dns_a=associated_ips[:1],
        dns_mx=[f"mx.{value}"],
        dns_ns=[f"ns1.{_pick(_REGISTRARS, value, 'ns').lower().replace(' ', '')}.com"],
        reputation_score=_reputation(value),
    )


def _enrich_hash(value: str) -> HashEnrichment:
    n = _stable_int(value)

    family = _pick(_MALWARE_FAMILIES, value, "family")

    # Known C2 domains (0-3)
    c2_count = n % 4
    c2_domains = [
        _pick(_MOCK_DOMAINS, value, f"c2_{i}") for i in range(c2_count)
    ]

    detection_count = (n % 3) + 1
    detections = list(
        set(_pick(_DETECTION_NAMES, value, f"det_{i}") for i in range(detection_count))
    )

    first_seen_days = (n % 365) + 1
    first_seen = datetime.utcnow() - timedelta(days=first_seen_days)

    return HashEnrichment(
        malware_family=family,
        file_type=_pick(_FILE_TYPES, value, "ftype"),
        file_size_bytes=((n % 900) + 100) * 1024,  # 100 KB – 1 MB
        first_seen=first_seen,
        known_c2_domains=c2_domains,
        detection_names=detections,
        reputation_score=_reputation(value),
    )
