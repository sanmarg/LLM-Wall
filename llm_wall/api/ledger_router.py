# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Blockchain ledger REST API router."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from llm_wall.ledger.node import get_ledger_node

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ledger", tags=["ledger"])


@router.get("/chain")
async def get_chain(
    start: int = 0, limit: int = 20
) -> list[dict[str, Any]]:
    """Returns a paginated slice of the blockchain.

    Args:
        start: Starting block index (inclusive).
        limit: Maximum number of blocks to return.

    Returns:
        List of block dicts.
    """
    ledger = get_ledger_node()
    full_chain = ledger.export_chain()
    return full_chain[start: start + limit]


@router.get("/stats")
async def get_ledger_stats() -> dict[str, Any]:
    """Returns chain height, pending events, and validity status.

    Returns:
        Ledger stats dict.
    """
    return get_ledger_node().get_stats()


@router.get("/verify")
async def verify_chain() -> dict[str, Any]:
    """Verifies the cryptographic integrity of the full chain.

    Returns:
        Dict with 'valid' boolean and 'height'.
    """
    ledger = get_ledger_node()
    valid = ledger.verify_chain()
    stats = ledger.get_stats()
    return {"valid": valid, "height": stats["height"]}


@router.get("/block/{block_index}")
async def get_block(block_index: int) -> dict[str, Any]:
    """Returns a specific block by index.

    Args:
        block_index: Zero-based block index.

    Returns:
        Block dict.

    Raises:
        HTTPException: 404 if block index is out of range.
    """
    ledger = get_ledger_node()
    chain = ledger.export_chain()
    if block_index < 0 or block_index >= len(chain):
        raise HTTPException(
            status_code=404,
            detail=f"Block #{block_index} not found.",
        )
    return chain[block_index]


@router.get("/proof/{block_index}/{event_id}")
async def get_merkle_proof(
    block_index: int, event_id: str
) -> dict[str, Any]:
    """Returns a Merkle inclusion proof for an audit event.

    Args:
        block_index: Block containing the event.
        event_id: UUID of the AuditEvent.

    Returns:
        Proof dict with 'root', 'proof', and 'valid' keys.
    """
    return get_ledger_node().get_merkle_proof(block_index, event_id)


@router.post("/flush")
async def flush_ledger() -> dict[str, Any]:
    """Forces immediate mining of pending audit events.

    Returns:
        Newly mined block dict, or message if no pending events.
    """
    ledger = get_ledger_node()
    block = ledger.flush_now()
    if block:
        return {"status": "mined", "block": block}
    return {"status": "no_pending_events"}
