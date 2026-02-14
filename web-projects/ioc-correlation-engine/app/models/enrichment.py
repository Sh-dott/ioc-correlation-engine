"""Enrichment result models for each IOC type."""

from __future__ import annotations

from datetime import datetime
from typing import Optional, Union

from pydantic import BaseModel

from app.models.ioc import IOC


class IPEnrichment(BaseModel):
    asn: str
    country: str
    hosting_provider: str
    open_ports: list[int]
    reputation_score: float  # 0.0 (benign) – 100.0 (malicious)
    abuse_contacts: list[str] = []


class DomainEnrichment(BaseModel):
    creation_date: datetime
    registrar: str
    ssl_issuer: Optional[str] = None
    associated_ips: list[str] = []
    dns_a: list[str] = []
    dns_mx: list[str] = []
    dns_ns: list[str] = []
    reputation_score: float


class HashEnrichment(BaseModel):
    malware_family: Optional[str] = None
    file_type: str
    file_size_bytes: int
    first_seen: datetime
    known_c2_domains: list[str] = []
    detection_names: list[str] = []
    reputation_score: float


class EnrichedIOC(BaseModel):
    """An IOC combined with its enrichment data."""

    ioc: IOC
    enrichment: Union[IPEnrichment, DomainEnrichment, HashEnrichment]

    @property
    def reputation(self) -> float:
        return self.enrichment.reputation_score
