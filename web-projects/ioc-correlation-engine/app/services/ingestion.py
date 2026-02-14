"""IOC ingestion — validates and normalizes incoming indicators."""

from __future__ import annotations

import logging
from datetime import datetime

from app.models.ioc import IOC, IOCBatchInput, IOCInput

logger = logging.getLogger(__name__)


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
    from app.models.ioc import IOCType, _IPV4_RE, _DOMAIN_RE, _SHA256_RE

    iocs: list[IOC] = []
    for line in raw_text.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split(",", maxsplit=1)]
        value = parts[0]

        if len(parts) == 2:
            ioc_type = IOCType(parts[1].lower())
        elif _IPV4_RE.match(value):
            ioc_type = IOCType.IP
        elif _SHA256_RE.match(value):
            ioc_type = IOCType.HASH
        elif _DOMAIN_RE.match(value):
            ioc_type = IOCType.DOMAIN
        else:
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
