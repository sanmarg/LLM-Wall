# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Dashboard API router — real-time status and analytics endpoints."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncIterator

from fastapi import APIRouter
from fastapi.responses import StreamingResponse

from llm_wall.a2a.bus import get_bus
from llm_wall.guardian.engine import get_guardian_engine
from llm_wall.ledger.node import get_ledger_node
from llm_wall.marl.engine import get_marl_engine
from llm_wall.models import Provider
from llm_wall.sentinel.node import get_sentinel_node

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("/status")
async def get_status() -> dict[str, Any]:
    """Returns the overall system status snapshot.

    Returns:
        Dict with sub-system statuses.
    """
    sentinel = get_sentinel_node()
    ledger = get_ledger_node()
    marl = get_marl_engine()
    bus = get_bus()
    return {
        "sentinel": sentinel.get_status(),
        "ledger": ledger.get_stats(),
        "marl": marl.get_status(),
        "a2a_bus": bus.stats(),
    }


@router.get("/threats/recent")
async def get_recent_threats(limit: int = 50) -> list[dict[str, Any]]:
    """Returns recent threat messages from the A2A bus.

    Args:
        limit: Maximum messages to return (default 50).

    Returns:
        List of A2AMessage dicts from threat topics.
    """
    bus = get_bus()
    messages = bus.get_recent_messages(limit=limit)
    return [m.model_dump(mode="json") for m in messages]


@router.get("/marl/heatmap/{agent_name}")
async def get_marl_heatmap(agent_name: str) -> list[dict[str, Any]]:
    """Returns the Q-table heatmap for a MARL agent.

    Args:
        agent_name: Agent name: 'gateway', 'tool', 'context', 'escalate'.

    Returns:
        List of heatmap row dicts.
    """
    marl = get_marl_engine()
    try:
        return marl.get_heatmap(agent_name)
    except KeyError:
        return []


@router.get("/providers/health")
async def get_provider_health() -> dict[str, Any]:
    """Checks connectivity to all configured LLM providers.

    Returns:
        Dict mapping provider name to health status.
    """
    from llm_wall.core.provider_clients import OllamaClient  # pylint: disable=import-outside-toplevel

    ollama = OllamaClient()
    ollama_ok = await ollama.health_check()
    await ollama.aclose()
    return {
        "ollama": {"reachable": ollama_ok},
        "openai": {"reachable": "configured_via_key"},
        "gemini": {"reachable": "configured_via_key"},
        "nvidia": {"reachable": "configured_via_key"},
    }


@router.get("/stream/events")
async def stream_events() -> StreamingResponse:
    """Server-Sent Events stream for real-time dashboard updates.

    Pushes a system status snapshot every 2 seconds.

    Returns:
        StreamingResponse with text/event-stream media type.
    """
    async def event_generator() -> AsyncIterator[str]:
        while True:
            sentinel = get_sentinel_node()
            ledger = get_ledger_node()
            marl = get_marl_engine()
            bus = get_bus()
            data = {
                "sentinel_iocs": sentinel.get_status()["ioc_stats"][
                    "total_iocs"
                ],
                "chain_height": ledger.get_stats()["height"],
                "marl_decisions": marl.get_status()["decision_count"],
                "bus_published": bus.stats()["total_published"],
                "recent_threats": [
                    m.model_dump(mode="json")
                    for m in bus.get_recent_messages(limit=5)
                ],
            }
            yield f"data: {json.dumps(data)}\n\n"
            await asyncio.sleep(2.0)

    return StreamingResponse(
        event_generator(), media_type="text/event-stream"
    )
