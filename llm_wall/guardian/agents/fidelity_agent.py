# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Dominion Fidelity Agent — Enforces that prompts stay within the prescribed purpose.

This agent combines:
1. Deterministic rule-based enforcement (zero-trust)
2. LLM-based semantic validation (secondary layer)

It NEVER relies solely on the LLM for enforcement.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from llm_wall.config import get_settings
from llm_wall.guardian.llm_clients import call_analysis_llm
from llm_wall.models import AgentSignal, LLMRequest, ThreatCategory

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------
# LLM schema for structured output
# ---------------------------------------------------------------------
_FIDELITY_SCHEMA = {
    "type": "object",
    "properties": {
        "aligned": {"type": "boolean"},
        "reason": {"type": "string"},
        "risk_score": {"type": "integer", "minimum": 0, "maximum": 100},
    },
    "required": ["aligned", "reason", "risk_score"],
}

# ---------------------------------------------------------------------
# Deterministic Zero-Trust Rules (PRIMARY ENFORCEMENT)
# ---------------------------------------------------------------------
_HIGH_RISK_REGEX = re.compile(
    r"\b(bomb|explosive|detonate|anthrax|cyanide|plutonium|weaponize|kill|attack)\b",
    re.IGNORECASE,
)

_OUT_OF_SCOPE_KEYWORDS = [
    "joke",
    "story",
    "poem",
    "fun",
    "game",
    "entertain",
    "roleplay",
    "pretend",
    "act as",
    "ignore previous instructions",
]


def _rule_based_check(prompt: str) -> tuple[int, list[str]]:
    """Deterministic enforcement before LLM.

    Returns:
        (risk_score, evidence)
    """
    evidence: list[str] = []
    prompt_lower = prompt.lower()

    # 🚨 Hard block: dangerous content
    if _HIGH_RISK_REGEX.search(prompt):
        evidence.append("Zero-Trust: High-risk dangerous keyword detected")
        return 100, evidence

    # ⚠️ Out-of-scope / misuse
    for keyword in _OUT_OF_SCOPE_KEYWORDS:
        if keyword in prompt_lower:
            evidence.append(f"Out-of-scope keyword detected: '{keyword}'")
            return 60, evidence

    return 0, evidence


# ---------------------------------------------------------------------
# Main Agent
# ---------------------------------------------------------------------
async def analyze_fidelity(request: LLMRequest) -> AgentSignal:
    """Checks if the user prompt aligns with the system's prescribed purpose.

    Args:
        request: The incoming LLM request.

    Returns:
        AgentSignal indicating whether the prompt is out-of-scope.
    """
    cfg = get_settings()
    purpose = cfg.app_system_purpose
    prompt = request.full_prompt

    # -----------------------------------------------------------------
    # Step 1: Deterministic rule-based enforcement (FAST + RELIABLE)
    # -----------------------------------------------------------------
    rule_score, rule_evidence = _rule_based_check(prompt)

    if rule_score >= 100:
        logger.warning("Fidelity: HARD BLOCK triggered (zero-trust rule)")
        return AgentSignal(
            agent_name="fidelity_agent",
            score=100,
            category=ThreatCategory.OUT_OF_SCOPE,
            confidence=1.0,
            evidence=rule_evidence,
        )

    if rule_score >= 60:
        logger.info("Fidelity: Out-of-scope detected via rules")
        return AgentSignal(
            agent_name="fidelity_agent",
            score=rule_score,
            category=ThreatCategory.OUT_OF_SCOPE,
            confidence=0.95,
            evidence=rule_evidence,
        )

    # -----------------------------------------------------------------
    # Step 2: LLM-based semantic validation (SECONDARY)
    # -----------------------------------------------------------------
    analysis_prompt = (
        "You are a STRICT enterprise AI policy enforcement system.\n\n"
        "The system has a SINGLE allowed purpose:\n"
        f"{purpose}\n\n"
        "User prompt:\n"
        f"{prompt}\n\n"
        "Rules:\n"
        "- If the prompt is NOT directly related to the purpose → aligned=false\n"
        "- Casual, creative, entertainment, or general questions → NOT allowed\n"
        "- Be extremely strict. Default to NOT aligned unless clearly valid\n\n"
        "Return JSON only."
    )

    try:
        result: dict[str, Any] = await call_analysis_llm(
            analysis_prompt,
            _FIDELITY_SCHEMA,
        )

        is_aligned = result.get("aligned", True)
        score = int(result.get("risk_score", 0))
        reason = result.get("reason", "No reason provided")

        logger.debug("Fidelity LLM result: %s", result)

        if not is_aligned:
            return AgentSignal(
                agent_name="fidelity_agent",
                score=max(score, 70),  # enforce minimum penalty
                category=ThreatCategory.OUT_OF_SCOPE,
                confidence=0.85,
                evidence=[reason],
            )

        return AgentSignal(
            agent_name="fidelity_agent",
            score=0,
            category=ThreatCategory.BENIGN,
            confidence=0.8,
            evidence=["Prompt aligned with system purpose"],
        )

    except Exception as exc:
        logger.warning(
            "Fidelity analysis failed → zero-trust fallback: %s",
            exc,
        )

        # 🚨 Zero-trust fallback
        return AgentSignal(
            agent_name="fidelity_agent",
            score=80,
            category=ThreatCategory.OUT_OF_SCOPE,
            confidence=1.0,
            evidence=[
                "Analysis failure → treated as high-risk (zero-trust fallback)"
            ],
        )