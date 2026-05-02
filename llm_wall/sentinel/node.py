# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Sentinel mesh node — threat intel orchestrator.

The SentinelNode ties together the IOCStore, GossipProtocol, and
Blockchain ledger node. It runs a background gossip loop and
exposes a clean API for adding IOCs and querying mesh status.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from llm_wall.a2a.bus import TOPIC_IOC_NEW, get_bus
from llm_wall.config import get_settings
from llm_wall.models import A2AMessage, IOC, ThreatCategory, ThreatReport
from llm_wall.sentinel.gossip import GossipProtocol
from llm_wall.sentinel.ioc_store import IOCStore

logger = logging.getLogger(__name__)


class SentinelNode:
    """Decentralised threat-intel Sentinel mesh node.

    Each deployed instance of LLM Wall is a Sentinel node. Nodes share
    newly discovered IOCs with all known peers via HTTP gossip; peers
    propagate further, forming an eventually-consistent mesh.

    Example:
        >>> node = SentinelNode()
        >>> await node.start()
        >>> node.ingest_threat(report, actor_ip="1.2.3.4")
        >>> status = node.get_status()
    """

    def __init__(self) -> None:
        """Initialises the Sentinel node from application settings."""
        cfg = get_settings()
        self._node_id: str = (
            cfg.sentinel_node_id or f"node-{uuid.uuid4().hex[:8]}"
        )
        self._ioc_store = IOCStore(
            max_ioc_age_hours=cfg.sentinel_max_ioc_age_hours
        )
        self._gossip = GossipProtocol(
            node_id=self._node_id,
            peers=cfg.peer_list,
        )
        self._gossip_interval: float = cfg.sentinel_gossip_interval_secs
        self._gossip_task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._threat_count: int = 0
        logger.info(
            "SentinelNode initialised: id=%s peers=%d",
            self._node_id,
            len(cfg.peer_list),
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Starts the background gossip loop."""
        if self._running:
            return
        self._running = True
        self._gossip_task = asyncio.create_task(
            self._gossip_loop(), name="sentinel-gossip"
        )
        logger.info(
            "SentinelNode started: gossip interval=%.0fs",
            self._gossip_interval,
        )

    async def stop(self) -> None:
        """Stops the gossip loop and closes network resources."""
        self._running = False
        if self._gossip_task:
            self._gossip_task.cancel()
            try:
                await self._gossip_task
            except asyncio.CancelledError:
                pass
        await self._gossip.aclose()
        logger.info("SentinelNode stopped.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_threat(
        self,
        report: ThreatReport,
        actor_ip: str = "unknown",
    ) -> list[IOC]:
        """Creates and stores IOCs derived from a ThreatReport.

        Extracts meaningful patterns from agent signals and stores them
        as IOCs so future matching can short-circuit full Guardian analysis.

        Args:
            report: Guardian ThreatReport from a blocked/quarantined request.
            actor_ip: Source IP for additional IOC metadata.

        Returns:
            List of newly created IOC objects.
        """
        new_iocs: list[IOC] = []
        self._threat_count += 1

        for signal in report.signals:
            for evidence in signal.evidence[:2]:
                if len(evidence) < 10 or evidence.startswith("No "):
                    continue
                # Extract the meaningful snippet from evidence text
                pattern = evidence.split("'")[1] if "'" in evidence else evidence
                pattern = pattern[:200].strip()
                if not pattern:
                    continue

                ioc = IOC(
                    category=signal.category,
                    pattern=pattern,
                    severity=min(10, max(1, signal.score // 10)),
                    source_node=self._node_id,
                )
                if self._ioc_store.add(ioc):
                    new_iocs.append(ioc)

        # Publish new IOCs to A2A bus
        if new_iocs:
            bus = get_bus()
            asyncio.ensure_future(
                bus.publish(
                    A2AMessage(
                        sender_id=self._node_id,
                        topic=TOPIC_IOC_NEW,
                        payload={
                            "count": len(new_iocs),
                            "request_id": report.request_id,
                        },
                        priority=7,
                    )
                )
            )
            logger.info(
                "Sentinel: %d new IOCs from request %s",
                len(new_iocs),
                report.request_id[:8],
            )

        return new_iocs

    def ingest_gossip(
        self, source_node: str, iocs: list[dict[str, Any]]
    ) -> int:
        """Ingests IOCs received via gossip from a peer node.

        Args:
            source_node: Peer node ID that sent the IOCs.
            iocs: List of raw IOC dicts (will be validated via Pydantic).

        Returns:
            Count of new IOCs accepted into the store.
        """
        count = 0
        for raw in iocs:
            try:
                ioc = IOC(**raw)
                if self._ioc_store.add(ioc):
                    count += 1
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Bad IOC from peer %s: %s", source_node, exc)
        logger.info(
            "Gossip ingested: source=%s accepted=%d/%d",
            source_node,
            count,
            len(iocs),
        )
        return count

    def match_prompt(self, prompt_text: str) -> list[IOC]:
        """Matches a prompt against the local IOC store.

        Args:
            prompt_text: Prompt text to scan.

        Returns:
            List of matching IOC objects sorted by severity.
        """
        return self._ioc_store.match(prompt_text)

    def evict_expired(self) -> int:
        """Evicts expired IOCs from the local store.

        Returns:
            Count of evicted IOCs.
        """
        return self._ioc_store.evict_expired()

    def get_status(self) -> dict[str, Any]:
        """Returns node status for the dashboard.

        Returns:
            Dict with node_id, ioc stats, peer list, and gossip stats.
        """
        cfg = get_settings()
        return {
            "node_id": self._node_id,
            "running": self._running,
            "threat_count": self._threat_count,
            "ioc_stats": self._ioc_store.stats(),
            "gossip_stats": self._gossip.stats(),
            "peer_count": len(cfg.peer_list),
            "peers": cfg.peer_list,
        }

    def get_ioc_store(self) -> IOCStore:
        """Returns the underlying IOCStore for Guardian integration.

        Returns:
            IOCStore instance.
        """
        return self._ioc_store

    # ------------------------------------------------------------------
    # Background loop
    # ------------------------------------------------------------------

    async def _gossip_loop(self) -> None:
        """Runs the periodic gossip broadcast loop.

        Broadcasts all local IOCs to peers every ``_gossip_interval`` secs.
        Also evicts expired IOCs on each cycle.
        """
        while self._running:
            await asyncio.sleep(self._gossip_interval)
            try:
                iocs = self._ioc_store.get_all()
                if iocs:
                    results = await self._gossip.broadcast_iocs(iocs)
                    total_sent = sum(results.values())
                    logger.debug(
                        "Gossip cycle: %d iocs → %d total sent to %d peers",
                        len(iocs),
                        total_sent,
                        len(results),
                    )
                evicted = self._ioc_store.evict_expired()
                if evicted:
                    logger.info("Gossip cycle: evicted %d IOCs.", evicted)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Gossip loop error: %s", exc)


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_sentinel_instance: SentinelNode | None = None


def get_sentinel_node() -> SentinelNode:
    """Returns the singleton SentinelNode instance.

    Returns:
        Global SentinelNode singleton.
    """
    global _sentinel_instance  # pylint: disable=global-statement
    if _sentinel_instance is None:
        _sentinel_instance = SentinelNode()
    return _sentinel_instance
