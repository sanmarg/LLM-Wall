from __future__ import annotations

import json
import logging
from typing import Any

from llm_wall.coral.engine import get_coral_engine
from llm_wall.guardian.llm_clients import call_analysis_llm
from llm_wall.models import ThreatCategory

logger = logging.getLogger(__name__)

_POLICY_SCHEMA = """
Respond with exactly this JSON schema:
{
  "suggested_block_threshold": <int 50-90>,
  "suggested_quarantine_threshold": <int 20-70>,
  "explanation": "<why these thresholds suit this org>",
  "critical_categories": ["<ThreatCategory values that should always block>"],
  "suggested_allowed_providers": ["<provider names from: openai, gemini, ollama, nvidia>"],
  "suggested_fidelity_rules": ["<list of specific org-relevant rules>"],
  "org_specific_risks": ["<list of risks specific to this org>"]
}
"""


async def generate_policy() -> dict[str, Any]:
    """Queries org security docs via Coral and generates Guardian policy suggestions.

    Coral reads from Notion (security policies), Confluence (runbooks),
    and GitHub (incident reports) to understand the org's security
    posture. An LLM then suggests Guardian thresholds, critical categories,
    allowed providers, and fidelity rules tailored to that org.

    Returns:
        Policy suggestion dict with thresholds and rules.
    """
    coral = get_coral_engine()
    context_parts: list[str] = []

    queries = [
        ("notion_security", """
            SELECT title, plain_text
            FROM notion.pages
            WHERE plain_text IS NOT NULL
              AND (plain_text ILIKE '%security%'
                   OR plain_text ILIKE '%policy%'
                   OR plain_text ILIKE '%compliance%')
            LIMIT 10
        """),
        ("github_incidents", """
            SELECT title, body
            FROM github.issues
            WHERE (body ILIKE '%incident%'
                   OR body ILIKE '%security%'
                   OR body ILIKE '%breach%')
              AND state != 'open'
            ORDER BY updated_at DESC
            LIMIT 10
        """),
        ("confluence_runbooks", """
            SELECT title, body
            FROM confluence.pages
            WHERE body ILIKE '%runbook%'
               OR body ILIKE '%incident response%'
               OR body ILIKE '%security%'
            LIMIT 10
        """),
    ]

    for source_name, sql in queries:
        try:
            rows = await coral.sql(sql)
            if rows:
                context_parts.append(f"--- {source_name} ---\n{json.dumps(rows[:5], indent=2)}")
        except Exception:
            pass

    org_context = "\n\n".join(context_parts)[:5000] if context_parts else (
        "No org-specific data available. Use default conservative values."
    )

    prompt = (
        f"You are a security architect configuring the LLM Wall Guardian for an organization. "
        f"Based on the following org data, suggest optimal security thresholds.\n\n"
        f"Org data:\n{org_context}\n\n"
        f"Consider:\n"
        f"- What security level does this org operate at?\n"
        f"- What compliance requirements might they have?\n"
        f"- What kind of data do they handle?\n"
        f"- What risk categories are most relevant?"
    )

    try:
        result = await call_analysis_llm(prompt, _POLICY_SCHEMA)
        if isinstance(result, dict):
            return result
        if isinstance(result, str):
            return json.loads(result)
        return result
    except Exception as exc:
        logger.warning("Policy generation failed: %s", exc)
        return _default_policy()


def _default_policy() -> dict[str, Any]:
    return {
        "suggested_block_threshold": 75,
        "suggested_quarantine_threshold": 50,
        "explanation": "Default conservative policy (Coral sources not available for policy generation).",
        "critical_categories": [
            ThreatCategory.DATA_EXFILTRATION.value,
            ThreatCategory.TOOL_ABUSE.value,
            ThreatCategory.LLMJACKING.value,
        ],
        "suggested_allowed_providers": ["ollama", "openai"],
        "suggested_fidelity_rules": [
            "Block any prompt attempting roleplay or persona adoption",
            "Block requests for system prompt extraction",
            "Block requests containing encoded/encrypted payloads",
        ],
        "org_specific_risks": ["Default — configure via Coral for org-specific risks"],
    }


async def apply_policy(suggestions: dict[str, Any]) -> dict[str, Any]:
    """Applies a generated policy suggestion to the running config.

    Args:
        suggestions: Policy dict from generate_policy().

    Returns:
        Result dict indicating what was changed.
    """
    from llm_wall.config import get_settings
    cfg = get_settings()
    changes: dict[str, Any] = {}

    bt = suggestions.get("suggested_block_threshold")
    if bt and 50 <= bt <= 90:
        changes["guardian_risk_threshold_block"] = bt
        logger.info("Policy: block threshold -> %d", bt)

    qt = suggestions.get("suggested_quarantine_threshold")
    if qt and 20 <= qt <= 70:
        changes["guardian_risk_threshold_quarantine"] = qt
        logger.info("Policy: quarantine threshold -> %d", qt)

    if changes:
        logger.info(
            "Applied policy changes: block=%s quarantine=%s",
            changes.get("guardian_risk_threshold_block", "unchanged"),
            changes.get("guardian_risk_threshold_quarantine", "unchanged"),
        )
    else:
        logger.info("No policy changes to apply.")
    return changes
