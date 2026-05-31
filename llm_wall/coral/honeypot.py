from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

from llm_wall.a2a.bus import get_bus
from llm_wall.coral.engine import get_coral_engine
from llm_wall.guardian.llm_clients import call_analysis_llm
from llm_wall.models import A2AMessage, IOC, ThreatCategory
from llm_wall.sentinel.node import get_sentinel_node

logger = logging.getLogger(__name__)

_GENERATION_SCHEMA = """
Respond with exactly this JSON schema — an array of objects:
[
  {
    "id": "HONEY-<3 digit number>",
    "honeypot_prompt": "<complete LLM prompt that an attacker might use>",
    "description": "<what this honeypot simulates>",
    "pattern": "<short unique string from the prompt that Sentinel can match>",
    "severity": <integer 1-10>
  }
]
Generate 3 honeypot prompts. Each should look realistic to an attacker.
"""


async def generate_honeypots(count: int = 3) -> list[dict[str, Any]]:
    """Generates decoy prompts using org data as context, adds to Sentinel IOCs.

    Coral queries real org data (repo names, API endpoints, team names,
    internal tool names). An LLM weaves these into realistic decoy prompts.
    The unique strings are registered as Sentinel IOCs so any request
    containing them gets flagged — catching attackers who probe with
    org-specific knowledge.

    Returns:
        List of generated honeypot dicts.
    """
    coral = get_coral_engine()
    context_parts: list[str] = []

    # Gather org context from Coral
    queries = [
        ("github_repos", "SELECT full_name, description, language FROM github.repos WHERE visibility = 'private' LIMIT 10"),
        ("github_issues", "SELECT title, body FROM github.issues WHERE LENGTH(body) > 50 LIMIT 10"),
        ("notion_pages", "SELECT title, plain_text FROM notion.pages WHERE plain_text IS NOT NULL LIMIT 10"),
        ("slack_channel_names", "SELECT name, purpose FROM slack.channels WHERE is_archived = false LIMIT 10"),
    ]

    for source_name, sql in queries:
        try:
            rows = await coral.sql(sql)
            if rows:
                context_parts.append(f"--- {source_name} ---\n{json.dumps(rows[:5], indent=2)}")
        except Exception:
            pass

    org_context = "\n\n".join(context_parts)[:4000] if context_parts else ""
    context_hint = (
        f"\n\nUse the following real org data as inspiration (do not include exact values):\n{org_context}"
        if org_context else ""
    )

    prompt = (
        f"You are a red-team security engineer. Generate {count} realistic decoy prompts "
        f"that look like they are targeting an organization's internal LLM systems."
        f"{context_hint}\n\n"
        f"Each honeypot prompt should:\n"
        f"1. Look like a genuine internal request (accessing data, asking for summaries, etc.)\n"
        f"2. Contain a unique keyword/phrase that Sentinel can detect\n"
        f"3. Include a subtle injection attempt that the Guardian would catch\n"
        f"4. Reference plausible internal systems or terminology"
    )

    try:
        result = await call_analysis_llm(prompt, _GENERATION_SCHEMA)
        raw_list = result if isinstance(result, list) else result.get("patterns", result.get("honeypots", []))
        if not raw_list:
            logger.warning("Honeypot generation returned empty list")
            return []

        honeypots: list[dict[str, Any]] = []
        sentinel = get_sentinel_node()
        bus = get_bus()
        added_iocs: list[IOC] = []

        for item in raw_list[:count]:
            pattern = item.get("pattern", item.get("honeypot_prompt", ""))[:200]
            if not pattern:
                continue
            ioc = IOC(
                pattern=pattern,
                category=ThreatCategory.PROMPT_INJECTION,
                severity=min(10, item.get("severity", 7)),
                source_node="honeypot_generator",
                ttl_hours=168,
            )
            if sentinel.get_ioc_store().add(ioc):
                added_iocs.append(ioc)
                honeypots.append(item)

        if added_iocs:
            asyncio_ensure = __import__("asyncio").ensure_future
            asyncio_ensure(
                bus.publish(
                    A2AMessage(
                        sender_id="honeypot_generator",
                        topic="honeypot.deployed",
                        payload={"count": len(added_iocs)},
                        priority=5,
                    )
                )
            )
            logger.info("Deployed %d honeypot IOCs to Sentinel", len(added_iocs))

        return honeypots
    except Exception as exc:
        logger.warning("Honeypot generation failed: %s", exc)
        return []


async def run_honeypot_cycle() -> dict[str, Any]:
    """One full honeypot generation and deployment cycle."""
    honeypots = await generate_honeypots()
    return {
        "deployed": len(honeypots),
        "honeypots": honeypots,
    }
