# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Intent classification Guardian agent.

Classifies the user's underlying intent into one of five categories
using a fast LLM call. Produces an AgentSignal with evidence.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from llm_wall.guardian.llm_clients import call_analysis_llm
from llm_wall.models import AgentSignal, ThreatCategory

logger = logging.getLogger(__name__)

_SCHEMA_HINT = """
Respond with exactly this JSON schema:
{
  "intent": "<benign|suspicious|harmful_content|data_exfiltration|goal_hijacking|llmjacking>",
  "confidence": <0.0-1.0>,
  "evidence": ["<reason 1>", "<reason 2>"]
}
"""

_INTENT_TO_CATEGORY: dict[str, ThreatCategory] = {
    "benign": ThreatCategory.BENIGN,
    "suspicious": ThreatCategory.PROMPT_INJECTION,
    "harmful_content": ThreatCategory.OUT_OF_SCOPE,
    "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
    "goal_hijacking": ThreatCategory.GOAL_HIJACKING,
    "llmjacking": ThreatCategory.LLMJACKING,
}

_INTENT_SCORES: dict[str, int] = {
    "benign": 0,
    "suspicious": 35,
    "harmful_content": 100,
    "data_exfiltration": 70,
    "goal_hijacking": 65,
    "llmjacking": 80,
}


async def analyse_intent(prompt_text: str) -> AgentSignal:
    """Classifies the intent of a prompt using an LLM Guardian call.

    Args:
        prompt_text: Full concatenated prompt content to analyse.

    Returns:
        AgentSignal with score, category, confidence, and evidence.
    """
    t0 = time.perf_counter()
    analysis_prompt = (
        f"Analyse the following user prompt and classify its intent:\n\n"
        f"---PROMPT START---\n{prompt_text[:3000]}\n---PROMPT END---\n\n"
        "Focus on: goal hijacking, data exfiltration, resource abuse "
        "(LLMjacking), or social engineering."
    )
    try:
        result: dict[str, Any] = await call_analysis_llm(
            analysis_prompt, _SCHEMA_HINT
        )
        intent = result.get("intent", "benign")
        confidence = float(result.get("confidence", 0.5))
        evidence = result.get("evidence", [])
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning("Intent agent LLM call failed: %s", exc)
        intent = "suspicious"
        confidence = 0.3
        evidence = [f"Analysis failed: {exc}"]

    score = _INTENT_SCORES.get(intent, 10)
    latency_ms = (time.perf_counter() - t0) * 1000

    logger.info(
        "IntentAgent: intent=%s score=%d confidence=%.2f latency=%.1fms",
        intent,
        score,
        confidence,
        latency_ms,
    )
    return AgentSignal(
        agent_name="intent_agent",
        score=score,
        category=_INTENT_TO_CATEGORY.get(intent, ThreatCategory.BENIGN),
        confidence=confidence,
        evidence=evidence[:5],
        latency_ms=latency_ms,
    )
