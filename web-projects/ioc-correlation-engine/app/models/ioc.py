"""IOC data models and validation."""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, field_validator


class IOCType(str, Enum):
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"


# ---------- Validation regexes ----------
_IPV4_RE = re.compile(
    r"^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$"
)
_DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,}$"
)
_SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
_HASH_RE = re.compile(r"^[a-fA-F0-9]{32,64}$")  # MD5(32), SHA1(40), SHA256(64)


class IOC(BaseModel):
    """Canonical IOC record."""

    value: str
    type: IOCType
    source: str = "manual"
    timestamp: datetime = datetime.utcnow()
    tags: list[str] = []

    @field_validator("value")
    @classmethod
    def validate_value(cls, v: str, info) -> str:
        ioc_type = info.data.get("type")
        if ioc_type == IOCType.IP and not _IPV4_RE.match(v):
            raise ValueError(f"Invalid IPv4 address: {v}")
        if ioc_type == IOCType.DOMAIN and not _DOMAIN_RE.match(v):
            raise ValueError(f"Invalid domain: {v}")
        if ioc_type == IOCType.HASH and not _HASH_RE.match(v):
            raise ValueError(f"Invalid hash (expected 32-64 hex chars): {v}")
        return v.lower()


class IOCInput(BaseModel):
    """Schema accepted on the ingestion endpoint."""

    value: str
    type: IOCType
    source: str = "manual"
    timestamp: Optional[datetime] = None
    tags: list[str] = []


class IOCBatchInput(BaseModel):
    """Wrapper for bulk IOC submission."""

    iocs: list[IOCInput]
