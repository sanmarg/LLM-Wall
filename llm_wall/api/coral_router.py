from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException

from llm_wall.coral.engine import get_coral_engine
from llm_wall.coral.honeypot import run_honeypot_cycle
from llm_wall.coral.investigator import get_investigator
from llm_wall.coral.pattern_hunter import get_pattern_hunter, get_org_patterns
from llm_wall.coral.policy_generator import apply_policy, generate_policy

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/coral", tags=["coral"])


@router.get("/status")
async def coral_status() -> dict[str, Any]:
    engine = get_coral_engine()
    investigator = get_investigator()
    hunter = get_pattern_hunter()
    return {
        "coral_engine": engine.stats(),
        "investigator": investigator.stats(),
        "pattern_hunter": hunter.stats(),
    }


@router.get("/sources")
async def list_sources() -> list[dict[str, str]]:
    engine = get_coral_engine()
    return await engine.list_sources()


@router.get("/discover")
async def discover_sources() -> list[dict[str, str]]:
    engine = get_coral_engine()
    return await engine.discover_sources()


@router.post("/sql")
async def run_sql(query: str) -> list[dict[str, Any]]:
    engine = get_coral_engine()
    results = await engine.sql(query)
    return results


@router.get("/investigations")
async def list_investigations(limit: int = 20) -> list[dict[str, Any]]:
    investigator = get_investigator()
    return investigator.get_recent_reports(limit=limit)


@router.get("/investigations/{investigation_id}")
async def get_investigation(investigation_id: str) -> dict[str, Any]:
    investigator = get_investigator()
    report = investigator.get_report(investigation_id)
    if not report:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return report


@router.post("/investigations/trigger")
async def trigger_investigation(
    request_id: str = "manual", risk_score: int = 50
) -> dict[str, Any]:
    investigator = get_investigator()
    report = await investigator.force_investigate(request_id, risk_score)
    if not report:
        raise HTTPException(status_code=500, detail="Investigation failed")
    return report.model_dump(mode="json")


@router.post("/patterns/hunt")
async def trigger_pattern_hunt() -> dict[str, Any]:
    hunter = get_pattern_hunter()
    summary = await hunter.hunt()
    return summary


@router.get("/patterns/org")
async def list_org_patterns() -> list[dict[str, Any]]:
    return get_org_patterns()


@router.post("/honeypots/generate")
async def trigger_honeypots() -> dict[str, Any]:
    result = await run_honeypot_cycle()
    return result


@router.post("/policy/generate")
async def trigger_policy_generation() -> dict[str, Any]:
    policy = await generate_policy()
    return policy


@router.post("/policy/apply")
async def trigger_policy_apply() -> dict[str, Any]:
    policy = await generate_policy()
    changes = await apply_policy(policy)
    return {"policy": policy, "changes": changes}
