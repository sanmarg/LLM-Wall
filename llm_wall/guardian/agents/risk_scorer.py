# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Risk scorer: aggregates all Guardian agent signals into a unified score.

Enhancements:
- HARD override for OUT_OF_SCOPE (policy enforcement, not just scoring)
- Strong dominant signal protection (cannot be averaged out)
- Safer handling of edge cases
"""

from __future__ import annotations

import logging
from typing import Any

from llm_wall.models import AgentSignal, RiskBand, ThreatCategory

logger = logging.getLogger(__name__)

# Agent weight map — injection and CoT detectors are given higher authority.
_AGENT_WEIGHTS: dict[str, float] = {
    "intent_agent": 0.20,
    "injection_agent": 0.35,
    "cot_inspector": 0.20,
    "fidelity_agent": 0.30,
    "ioc_matcher": 0.05,
}

_DEFAULT_WEIGHT: float = 0.20


def compute_risk_score(signals: list[AgentSignal]) -> int:
    """Computes the weighted aggregate risk score from agent signals.

    Key Security Guarantees:
    - OUT_OF_SCOPE is treated as a HARD policy violation
    - High-confidence threats cannot be diluted via averaging

    Args:
        signals: List of AgentSignal objects from Guardian agents.

    Returns:
        Integer risk score in range [0, 100].
    """
    if not signals:
        return 0

    # ------------------------------------------------------------------
    # 🔴 HARD POLICY ENFORCEMENT (CRITICAL FIX)
    # ------------------------------------------------------------------
    for signal in signals:
        if (
            signal.category == ThreatCategory.OUT_OF_SCOPE
            and signal.score >= 70
        ):
            logger.warning(
                "Hard block triggered by OUT_OF_SCOPE: agent=%s score=%d",
                signal.agent_name,
                signal.score,
            )
            # Force high-risk classification (cannot be averaged down)
            return max(80, signal.score)

    # ------------------------------------------------------------------
    # 🧮 STANDARD WEIGHTED SCORING
    # ------------------------------------------------------------------
    total_weight: float = 0.0
    weighted_sum: float = 0.0

    for signal in signals:
        weight = _AGENT_WEIGHTS.get(signal.agent_name, _DEFAULT_WEIGHT)
        effective_weight = weight * signal.confidence

        weighted_sum += signal.score * effective_weight
        total_weight += effective_weight

    aggregated = int(weighted_sum / total_weight) if total_weight > 0 else 0

    # ------------------------------------------------------------------
    # 🔥 DOMINANT SIGNAL OVERRIDE (ANTI-DILUTION)
    # ------------------------------------------------------------------
    for signal in signals:
        if signal.score >= 70 and signal.confidence >= 0.8:
            aggregated = max(aggregated, signal.score)
            logger.info(
                "Dominant signal override: agent=%s score=%d",
                signal.agent_name,
                signal.score,
            )

    aggregated = min(100, max(0, aggregated))
    return aggregated


def determine_primary_category(
    signals: list[AgentSignal],
) -> ThreatCategory:
    """Returns the primary threat category from the highest-scoring signal."""
    non_benign = [
        s for s in signals
        if s.category != ThreatCategory.BENIGN and s.score > 0
    ]
    if not non_benign:
        return ThreatCategory.BENIGN

    return max(
        non_benign,
        key=lambda s: s.score * s.confidence
    ).category


def build_explanation(
    risk_score: int,
    signals: list[AgentSignal],
    primary_category: ThreatCategory,
) -> str:
    """Builds a human-readable explanation of the risk decision."""
    band = RiskBand.from_score(risk_score)

    lines: list[str] = [
        f"Risk: {risk_score}/100 ({band.value.upper()}) | "
        f"Primary threat: {primary_category.value}"
    ]

    for sig in signals:
        if sig.score > 0:
            lines.append(
                f"  [{sig.agent_name}] score={sig.score} "
                f"conf={sig.confidence:.2f}: "
                + (sig.evidence[0] if sig.evidence else "")
            )

    return "\n".join(lines)