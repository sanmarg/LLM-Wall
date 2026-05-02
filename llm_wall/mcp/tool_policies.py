# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""MCP tool policy definitions and evaluation logic."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from llm_wall.models import ThreatAction

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ToolPolicy:
    """Immutable tool security policy.

    Attributes:
        level: Human-readable risk level label.
        block_threshold: Risk score ≥ this → BLOCK.
        quarantine_threshold: Risk score ≥ this → QUARANTINE.
    """

    level: str
    block_threshold: int
    quarantine_threshold: int

    def evaluate(self, risk_score: int) -> ThreatAction:
        """Evaluates a risk score against this policy.

        Args:
            risk_score: Integer 0-100 risk score.

        Returns:
            ThreatAction to apply (ALLOW, QUARANTINE, or BLOCK).
        """
        if risk_score >= self.block_threshold:
            return ThreatAction.BLOCK
        if risk_score >= self.quarantine_threshold:
            return ThreatAction.QUARANTINE
        return ThreatAction.ALLOW


# Pre-defined policies ordered by sensitivity.
_POLICIES: dict[str, ToolPolicy] = {
    "low": ToolPolicy(
        level="low",
        block_threshold=80,
        quarantine_threshold=60,
    ),
    "medium": ToolPolicy(
        level="medium",
        block_threshold=60,
        quarantine_threshold=40,
    ),
    "high": ToolPolicy(
        level="high",
        block_threshold=40,
        quarantine_threshold=20,
    ),
    "critical": ToolPolicy(
        level="critical",
        block_threshold=20,
        quarantine_threshold=10,
    ),
}


def get_policy(level: str) -> ToolPolicy:
    """Returns the ToolPolicy for a given risk level.

    Args:
        level: One of 'low', 'medium', 'high', 'critical'.

    Returns:
        Corresponding ToolPolicy.  Defaults to 'medium' for unknown levels.
    """
    policy = _POLICIES.get(level.lower(), _POLICIES["medium"])
    if level.lower() not in _POLICIES:
        logger.warning(
            "Unknown tool policy level '%s', defaulting to 'medium'.", level
        )
    return policy
