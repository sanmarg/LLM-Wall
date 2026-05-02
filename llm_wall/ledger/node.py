# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Ledger node: exposes the blockchain to the application layer.

Wraps the Blockchain with a high-level API for adding security events,
flushing blocks, and querying the chain.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any

from llm_wall.config import get_settings
from llm_wall.ledger.blockchain import Blockchain
from llm_wall.models import AuditEvent, LLMRequest, Provider, ThreatReport

logger = logging.getLogger(__name__)


class LedgerNode:
    """Blockchain ledger node for immutable security audit recording.

    Wraps Blockchain with request lifecycle integration: converts
    Guardian ThreatReports into AuditEvents and manages background
    block flushing.

    Example:
        >>> ledger = LedgerNode()
        >>> await ledger.start()
        >>> ledger.record(request, report, actor_ip="1.2.3.4")
        >>> chain_data = ledger.export_chain()
    """

    def __init__(self) -> None:
        """Initialises the ledger node from application settings."""
        cfg = get_settings()
        node_id = f"ledger-{uuid.uuid4().hex[:8]}"
        self._chain = Blockchain(
            node_id=node_id,
            difficulty=cfg.ledger_difficulty,
            persist_path=cfg.ledger_persist_path,
        )
        self._flush_interval: float = 60.0  # seconds
        self._flush_task: asyncio.Task[None] | None = None
        self._record_count: int = 0
        logger.info(
            "LedgerNode initialised: height=%d difficulty=%d",
            self._chain.height,
            cfg.ledger_difficulty,
        )

    async def start(self) -> None:
        """Starts the background block-flush loop."""
        self._flush_task = asyncio.create_task(
            self._flush_loop(), name="ledger-flush"
        )
        logger.info("LedgerNode background flush loop started.")

    async def stop(self) -> None:
        """Stops the flush loop and mines any pending events."""
        if self._flush_task:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
        self._chain.flush()
        logger.info("LedgerNode stopped; final flush complete.")

    def record(
        self,
        request: "LLMRequest",
        report: ThreatReport,
        actor_ip: str = "unknown",
    ) -> None:
        """Records a security event derived from a ThreatReport.

        Args:
            request: Originating LLM request.
            report: Guardian ThreatReport for this request.
            actor_ip: Source IP address of the caller.
        """
        full_prompt = request.full_prompt
        snippet = (full_prompt[:100] + "..") if len(full_prompt) > 100 else full_prompt
        actor_name = str(request.metadata.get("user_id") or request.metadata.get("client_id") or "anonymous")

        event = AuditEvent(
            request_id=request.request_id,
            action=report.action,
            risk_score=report.risk_score,
            primary_category=report.primary_category,
            provider=request.provider,
            model=request.model,
            actor_ip=actor_ip,
            actor_name=actor_name,
            prompt_snippet=snippet,
            signals_summary=[
                f"{s.agent_name}:{s.score}" for s in report.signals
            ],
        )
        self._chain.add_event(event)
        self._record_count += 1
        logger.debug(
            "Ledger event queued: request=%s action=%s risk=%d",
            request.request_id[:8],
            report.action.value,
            report.risk_score,
        )

    def flush_now(self) -> dict[str, Any] | None:
        """Forces immediate mining of pending events.

        Returns:
            Dict representation of the newly mined block, or None if empty.
        """
        block = self._chain.flush()
        return block.to_dict() if block else None

    def export_chain(self) -> list[dict[str, Any]]:
        """Exports the full blockchain as a list of dicts.

        Returns:
            List of block dicts in ascending index order.
        """
        return self._chain.export_chain()

    def verify_chain(self) -> bool:
        """Verifies the blockchain's cryptographic integrity.

        Returns:
            True if the chain is valid, False if tampered.
        """
        return self._chain.is_valid()

    def get_merkle_proof(
        self, block_index: int, event_id: str
    ) -> dict[str, Any]:
        """Returns a Merkle inclusion proof for a specific event.

        Args:
            block_index: Index of the block to probe.
            event_id: UUID of the AuditEvent.

        Returns:
            Proof dict from Blockchain.get_merkle_proof().
        """
        return self._chain.get_merkle_proof(block_index, event_id)

    def get_stats(self) -> dict[str, Any]:
        """Returns ledger statistics for the dashboard.

        Returns:
            Dict with height, pending, record_count, and validity.
        """
        return {
            "height": self._chain.height,
            "pending_events": self._chain.pending_count,
            "total_records": self._record_count,
            "chain_valid": self._chain.is_valid(),
        }

    async def _flush_loop(self) -> None:
        """Periodically flushes pending events into new blocks."""
        while True:
            await asyncio.sleep(self._flush_interval)
            try:
                block = self._chain.flush()
                if block:
                    logger.info(
                        "Scheduled flush: block #%d mined (%d events)",
                        block.index,
                        len(block.data.events),
                    )
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("Ledger flush error: %s", exc)


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_ledger_instance: LedgerNode | None = None


def get_ledger_node() -> LedgerNode:
    """Returns the singleton LedgerNode instance.

    Returns:
        Global LedgerNode singleton.
    """
    global _ledger_instance  # pylint: disable=global-statement
    if _ledger_instance is None:
        _ledger_instance = LedgerNode()
    return _ledger_instance
