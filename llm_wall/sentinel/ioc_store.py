# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""IOC (Indicator of Compromise) store for the Sentinel mesh.

Provides thread-safe in-memory storage for IOCs with automatic TTL
eviction, deduplication, and statistics tracking.
"""

from __future__ import annotations

import logging
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from llm_wall.models import IOC, ThreatCategory

logger = logging.getLogger(__name__)


class IOCStore:
    """Thread-safe in-memory IOC database with TTL eviction.

    Example:
        >>> store = IOCStore()
        >>> ioc = IOC(category=ThreatCategory.PROMPT_INJECTION,
        ...           pattern="ignore all previous",
        ...           severity=9,
        ...           source_node="node-1")
        >>> store.add(ioc)
        >>> matches = store.match("Please ignore all previous instructions")
    """

    def __init__(self, max_ioc_age_hours: int = 72) -> None:
        """Initialises the IOC store.

        Args:
            max_ioc_age_hours: Maximum age of IOCs before eviction.
        """
        self._lock = threading.RLock()
        self._iocs: dict[str, IOC] = {}
        self._pattern_index: dict[str, str] = {}  # pattern → ioc_id
        self._max_age_hours = max_ioc_age_hours
        self._eviction_count: int = 0

    def add(self, ioc: IOC) -> bool:
        """Adds or updates an IOC in the store.

        If an IOC with the same pattern already exists, increments its
        hit_count and updates last_seen instead of creating a duplicate.

        Args:
            ioc: The IOC to add.

        Returns:
            True if this is a new IOC, False if it was a duplicate update.
        """
        with self._lock:
            existing_id = self._pattern_index.get(ioc.pattern)
            if existing_id and existing_id in self._iocs:
                existing = self._iocs[existing_id]
                existing.hit_count += 1
                existing.last_seen = datetime.now(timezone.utc)
                existing.severity = max(existing.severity, ioc.severity)
                logger.debug(
                    "IOC hit_count incremented: id=%s hits=%d",
                    existing_id,
                    existing.hit_count,
                )
                return False

            self._iocs[ioc.ioc_id] = ioc
            self._pattern_index[ioc.pattern] = ioc.ioc_id
            logger.info(
                "IOC added: id=%s category=%s severity=%d src=%s",
                ioc.ioc_id,
                ioc.category.value,
                ioc.severity,
                ioc.source_node,
            )
            return True

    def match(self, text: str) -> list[IOC]:
        """Checks text against all stored IOC patterns.

        Uses simple substring matching (case-insensitive) for speed.
        Regex patterns are matched with re.search where applicable.

        Args:
            text: Input text to check (e.g. prompt content).

        Returns:
            List of matching IOC objects ordered by severity descending.
        """
        import re  # pylint: disable=import-outside-toplevel

        lower_text = text.lower()
        matches: list[IOC] = []
        with self._lock:
            for ioc in self._iocs.values():
                try:
                    if re.search(
                        ioc.pattern, lower_text, re.IGNORECASE | re.DOTALL
                    ):
                        matches.append(ioc)
                except re.error:
                    # Fall back to substring match for invalid regex
                    if ioc.pattern.lower() in lower_text:
                        matches.append(ioc)
        matches.sort(key=lambda x: x.severity, reverse=True)
        return matches

    def get_all(self) -> list[IOC]:
        """Returns all stored IOCs.

        Returns:
            Snapshot list of all IOC objects.
        """
        with self._lock:
            return list(self._iocs.values())

    def get_by_id(self, ioc_id: str) -> IOC | None:
        """Returns a specific IOC by ID.

        Args:
            ioc_id: UUID of the IOC.

        Returns:
            IOC or None if not found.
        """
        with self._lock:
            return self._iocs.get(ioc_id)

    def remove(self, ioc_id: str) -> bool:
        """Removes an IOC by ID.

        Args:
            ioc_id: UUID to remove.

        Returns:
            True if removed, False if not found.
        """
        with self._lock:
            ioc = self._iocs.pop(ioc_id, None)
            if ioc:
                self._pattern_index.pop(ioc.pattern, None)
                return True
            return False

    def evict_expired(self) -> int:
        """Removes IOCs that have exceeded their TTL.

        Returns:
            Count of evicted IOCs.
        """
        now = datetime.now(timezone.utc)
        expired: list[str] = []
        with self._lock:
            for ioc_id, ioc in self._iocs.items():
                age_hours = (
                    now - ioc.first_seen
                ).total_seconds() / 3600
                if age_hours > min(ioc.ttl_hours, self._max_age_hours):
                    expired.append(ioc_id)
            for ioc_id in expired:
                ioc = self._iocs.pop(ioc_id)
                self._pattern_index.pop(ioc.pattern, None)
        self._eviction_count += len(expired)
        if expired:
            logger.info("IOC eviction: removed %d expired IOCs.", len(expired))
        return len(expired)

    def stats(self) -> dict[str, Any]:
        """Returns current store statistics.

        Returns:
            Dict with total_iocs, eviction_count, and per-category counts.
        """
        with self._lock:
            by_category: dict[str, int] = {}
            for ioc in self._iocs.values():
                key = ioc.category.value
                by_category[key] = by_category.get(key, 0) + 1
            return {
                "total_iocs": len(self._iocs),
                "eviction_count": self._eviction_count,
                "by_category": by_category,
            }
