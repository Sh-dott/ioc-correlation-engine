"""IOC ingestion — validates and normalizes incoming indicators."""

from __future__ import annotations

import logging
import re
from datetime import datetime
from typing import Any

from app.models.ioc import IOC, IOCBatchInput, IOCInput, IOCType, _IPV4_RE, _DOMAIN_RE, _SHA256_RE

logger = logging.getLogger(__name__)

# ── Type alias mapping: common names → canonical type ──
_TYPE_ALIASES: dict[str, IOCType] = {
    "ip": IOCType.IP,
    "ipv4": IOCType.IP,
    "ipv4-addr": IOCType.IP,
    "ip-src": IOCType.IP,
    "ip-dst": IOCType.IP,
    "ipaddress": IOCType.IP,
    "ip_address": IOCType.IP,
    "ip-address": IOCType.IP,
    "domain": IOCType.DOMAIN,
    "domain-name": IOCType.DOMAIN,
    "hostname": IOCType.DOMAIN,
    "fqdn": IOCType.DOMAIN,
    "url": IOCType.DOMAIN,
    "hash": IOCType.HASH,
    "sha256": IOCType.HASH,
    "sha-256": IOCType.HASH,
    "sha1": IOCType.HASH,
    "sha-1": IOCType.HASH,
    "md5": IOCType.HASH,
    "file-hash": IOCType.HASH,
    "file_hash": IOCType.HASH,
    "filehash": IOCType.HASH,
}

# Fields to look for the IOC value in, in priority order
_VALUE_FIELDS = ("value", "indicator", "ioc", "ioc_value", "observable", "pattern", "data", "artifact")
_TYPE_FIELDS = ("type", "ioc_type", "indicator_type", "observable_type", "category")
_SOURCE_FIELDS = ("source", "provider", "feed", "origin", "reporter")
_TAG_FIELDS = ("tags", "labels", "categories")

# URL → domain extraction
_URL_RE = re.compile(r"^https?://([^/:]+)")


def _detect_type(value: str) -> IOCType | None:
    """Auto-detect IOC type from value string."""
    if _IPV4_RE.match(value):
        return IOCType.IP
    if _SHA256_RE.match(value):
        return IOCType.HASH
    # Also accept md5 (32 hex) and sha1 (40 hex) as hash type
    if re.match(r"^[a-fA-F0-9]{32}$", value) or re.match(r"^[a-fA-F0-9]{40}$", value):
        return IOCType.HASH
    if _DOMAIN_RE.match(value):
        return IOCType.DOMAIN
    # Extract domain from URL
    m = _URL_RE.match(value)
    if m:
        return IOCType.DOMAIN
    return None


def _extract_domain_from_url(value: str) -> str:
    """If value is a URL, extract the domain; otherwise return as-is."""
    m = _URL_RE.match(value)
    return m.group(1) if m else value


def _pick_field(obj: dict, fields: tuple, default: Any = None) -> Any:
    """Return the first matching field value from a dict."""
    for f in fields:
        if f in obj and obj[f] is not None:
            return obj[f]
    return default


def _resolve_type(raw_type: str | None, value: str) -> IOCType | None:
    """Resolve an IOC type from a type string alias or auto-detect from value."""
    if raw_type:
        t = _TYPE_ALIASES.get(raw_type.lower().strip())
        if t:
            return t
    return _detect_type(value)


def normalize_raw_payload(data: Any) -> list[dict]:
    """Accept any common IOC JSON shape and return a flat list of dicts.

    Supported formats:
        {"iocs": [...]}           — SYNAPSE native
        {"indicators": [...]}     — common TIP export
        {"objects": [...]}        — STIX bundle
        {"data": [...]}           — generic wrapper
        [...]                     — bare array
        {"value": "...", ...}     — single IOC object
    """
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        # Try common wrapper keys
        for key in ("iocs", "indicators", "objects", "data", "items", "results", "ioc_list"):
            if key in data and isinstance(data[key], list):
                return data[key]
        # Single IOC object
        if any(f in data for f in _VALUE_FIELDS):
            return [data]
    return []


def ingest_flexible(data: Any) -> list[IOC]:
    """Ingest IOCs from any common JSON format with auto-detection."""
    raw_items = normalize_raw_payload(data)
    iocs: list[IOC] = []

    for item in raw_items:
        if not isinstance(item, dict):
            # Plain string value
            if isinstance(item, str):
                item = {"value": item}
            else:
                continue

        value = _pick_field(item, _VALUE_FIELDS)
        if not value or not isinstance(value, str):
            continue

        value = value.strip()
        if not value:
            continue

        # Extract domain from URL
        value = _extract_domain_from_url(value)

        raw_type = _pick_field(item, _TYPE_FIELDS)
        ioc_type = _resolve_type(str(raw_type) if raw_type else None, value)
        if ioc_type is None:
            logger.warning("Cannot determine type for: %s (type field: %s)", value, raw_type)
            continue

        source = _pick_field(item, _SOURCE_FIELDS, "manual")
        tags = _pick_field(item, _TAG_FIELDS, [])
        if isinstance(tags, str):
            tags = [t.strip() for t in tags.split(",")]

        # Parse timestamp from various field names
        ts = None
        for tf in ("timestamp", "created", "date", "first_seen", "last_seen", "time"):
            if tf in item and item[tf]:
                try:
                    ts = datetime.fromisoformat(str(item[tf]).replace("Z", "+00:00"))
                except (ValueError, TypeError):
                    pass
                break

        try:
            iocs.append(
                IOC(
                    value=value,
                    type=ioc_type,
                    source=str(source),
                    timestamp=ts or datetime.utcnow(),
                    tags=tags if isinstance(tags, list) else [],
                )
            )
        except Exception as exc:
            logger.warning("Skipping invalid IOC %s: %s", value, exc)

    logger.info("Flexible ingest: accepted %d / %d items", len(iocs), len(raw_items))
    return iocs


def ingest_batch(batch: IOCBatchInput) -> list[IOC]:
    """Convert raw input records into validated IOC objects."""
    validated: list[IOC] = []
    for item in batch.iocs:
        try:
            ioc = _normalize(item)
            validated.append(ioc)
        except Exception as exc:
            logger.warning("Skipping invalid IOC %s: %s", item.value, exc)
    logger.info("Ingested %d / %d IOCs", len(validated), len(batch.iocs))
    return validated


def ingest_text(raw_text: str) -> list[IOC]:
    """Parse newline-separated IOCs with auto-type detection.

    Accepted line format:  ``<value>``  or  ``<value>,<type>``
    """
    iocs: list[IOC] = []
    for line in raw_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",", maxsplit=1)]
        value = parts[0]

        if len(parts) == 2:
            try:
                ioc_type = IOCType(parts[1].lower())
            except ValueError:
                ioc_type = _TYPE_ALIASES.get(parts[1].lower().strip())
                if not ioc_type:
                    ioc_type = _detect_type(value)
        else:
            ioc_type = _detect_type(value)

        if not ioc_type:
            logger.warning("Cannot auto-detect type for: %s", value)
            continue

        try:
            iocs.append(
                IOC(
                    value=value,
                    type=ioc_type,
                    source="text-input",
                    timestamp=datetime.utcnow(),
                )
            )
        except Exception as exc:
            logger.warning("Skipping invalid IOC %s: %s", value, exc)
    return iocs


def _normalize(item: IOCInput) -> IOC:
    return IOC(
        value=item.value,
        type=item.type,
        source=item.source,
        timestamp=item.timestamp or datetime.utcnow(),
        tags=item.tags,
    )
