# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Pattern management REST API router.

Exposes endpoints to:
    - Trigger an on-demand pattern update from threat-intel feeds
    - View all evolved patterns in the DB
    - Check updater status
    - Manually add custom patterns
    - Promote IOC patterns on demand
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from llm_wall.guardian.pattern_updater import (
    _validate_regex,
    _compute_pattern_hash,
    _load_evolved_patterns,
    _save_evolved_patterns,
    get_pattern_updater,
)
from llm_wall.sentinel.node import get_sentinel_node

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/patterns", tags=["patterns"])


class CustomPatternRequest(BaseModel):
    """Request body for adding a custom pattern."""

    name: str = Field(description="Short descriptive name.")
    pattern: str = Field(description="Python regex pattern string.")
    severity: int = Field(ge=1, le=10, description="Severity level 1-10.")
    category: str = Field(
        default="prompt_injection",
        description=(
            "Threat category: prompt_injection | jailbreak | "
            "goal_hijacking | data_exfiltration | tool_abuse | llmjacking"
        ),
    )


@router.get("/status")
async def get_pattern_status() -> dict[str, Any]:
    """Returns the pattern updater status and evolved pattern count.

    Returns:
        Dict with updater status, last run time, and pattern stats.
    """
    updater = get_pattern_updater()
    status = await updater.get_status()
    data = _load_evolved_patterns()
    status["evolved_patterns_metadata"] = data.get("metadata", {})
    return status


@router.get("/evolved")
async def list_evolved_patterns(
    category: str | None = None,
    min_severity: int = 1,
) -> list[dict[str, Any]]:
    """Lists all auto-evolved patterns, with optional filtering.

    Args:
        category: Optional category filter string.
        min_severity: Minimum severity (1-10).

    Returns:
        Filtered list of evolved pattern dicts.
    """
    patterns = _load_evolved_patterns().get("patterns", [])
    if category:
        patterns = [p for p in patterns if p.get("category") == category]
    patterns = [p for p in patterns if p.get("severity", 1) >= min_severity]
    return patterns


@router.post("/update")
async def trigger_update() -> dict[str, Any]:
    """Triggers an immediate pattern update from all configured feeds.

    Fetches threat-intel from public sources, synthesises new regex
    patterns via Guardian LLM, and hot-reloads into the injection agent.

    Returns:
        Summary dict with per-source pattern counts.
    """
    sentinel = get_sentinel_node()
    updater = get_pattern_updater(ioc_store=sentinel.get_ioc_store())
    result = await updater.run_now()
    return {"status": "complete", "summary": result}


@router.post("/promote-iocs")
async def promote_ioc_patterns_endpoint(
    min_hits: int = 3,
) -> dict[str, int]:
    """Promotes high-hit IOC patterns into the evolved pattern database.

    Args:
        min_hits: Minimum IOC hit count to qualify for promotion.

    Returns:
        Dict with 'promoted' count.
    """
    from llm_wall.guardian.pattern_updater import promote_ioc_patterns  # noqa

    sentinel = get_sentinel_node()
    promoted = promote_ioc_patterns(
        sentinel.get_ioc_store(), min_hits=min_hits
    )
    return {"promoted": promoted}


@router.post("/custom")
async def add_custom_pattern(
    body: CustomPatternRequest,
) -> dict[str, Any]:
    """Adds a manually specified custom pattern to the evolved DB.

    Validates the regex before storing. Hot-reloads immediately.

    Args:
        body: CustomPatternRequest with name, pattern, severity, category.

    Returns:
        Created pattern dict.

    Raises:
        HTTPException: 400 if the pattern is an invalid regex.
    """
    if not _validate_regex(body.pattern):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid regex pattern: {body.pattern!r}",
        )
    data = _load_evolved_patterns()
    h = _compute_pattern_hash(body.pattern)
    for existing in data["patterns"]:
        if existing.get("hash") == h:
            raise HTTPException(
                status_code=409,
                detail="Pattern already exists in evolved DB.",
            )

    new_pat: dict[str, Any] = {
        "id": f"CUSTOM-{h.upper()}",
        "name": body.name,
        "pattern": body.pattern,
        "severity": body.severity,
        "category": body.category,
        "source": "manual",
        "auto_generated": False,
        "hash": h,
    }
    data["patterns"].append(new_pat)
    _save_evolved_patterns(data)

    # Hot-reload
    updater = get_pattern_updater()
    updater._hot_reload([new_pat])  # pylint: disable=protected-access

    logger.info("Custom pattern added: %s", body.name)
    return new_pat


@router.delete("/evolved/{pattern_hash}")
async def delete_evolved_pattern(pattern_hash: str) -> dict[str, str]:
    """Removes an evolved pattern from the database by its hash.

    Args:
        pattern_hash: 8-character pattern hash.

    Returns:
        Dict with 'status' message.

    Raises:
        HTTPException: 404 if pattern not found.
    """
    data = _load_evolved_patterns()
    original_count = len(data["patterns"])
    data["patterns"] = [
        p for p in data["patterns"] if p.get("hash") != pattern_hash
    ]
    if len(data["patterns"]) == original_count:
        raise HTTPException(
            status_code=404,
            detail=f"Pattern with hash '{pattern_hash}' not found.",
        )
    _save_evolved_patterns(data)
    return {"status": f"Pattern '{pattern_hash}' removed."}
