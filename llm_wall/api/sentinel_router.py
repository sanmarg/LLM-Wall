# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Sentinel mesh REST API router."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from llm_wall.models import IOC
from llm_wall.sentinel.node import get_sentinel_node

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sentinel", tags=["sentinel"])


@router.get("/status")
async def sentinel_status() -> dict[str, Any]:
    """Returns the Sentinel node status and IOC statistics.

    Returns:
        Node status dict from SentinelNode.get_status().
    """
    return get_sentinel_node().get_status()


@router.get("/iocs")
async def list_iocs() -> list[dict[str, Any]]:
    """Returns all IOCs currently in the local store.

    Returns:
        List of IOC dicts sorted by severity descending.
    """
    node = get_sentinel_node()
    iocs = node.get_ioc_store().get_all()
    iocs.sort(key=lambda i: i.severity, reverse=True)
    return [i.model_dump(mode="json") for i in iocs]


@router.post("/gossip")
async def receive_gossip(payload: dict[str, Any]) -> dict[str, int]:
    """Receives gossip IOCs from a peer Sentinel node.

    Args:
        payload: Dict with 'source_node' and 'iocs' list.

    Returns:
        Dict with 'accepted' count.
    """
    source = payload.get("source_node", "unknown")
    iocs_raw = payload.get("iocs", [])
    node = get_sentinel_node()
    accepted = node.ingest_gossip(source, iocs_raw)
    return {"accepted": accepted}


@router.post("/iocs/match")
async def match_ioc(body: dict[str, str]) -> dict[str, Any]:
    """Matches a text string against the local IOC store.

    Args:
        body: Dict with 'text' key.

    Returns:
        Dict with 'matches' list of matching IOCs.
    """
    text = body.get("text", "")
    if not text:
        raise HTTPException(status_code=400, detail="'text' is required.")
    node = get_sentinel_node()
    matches = node.match_prompt(text)
    return {
        "matches": [m.model_dump(mode="json") for m in matches],
        "count": len(matches),
    }
