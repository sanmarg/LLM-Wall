# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""MARL environment definitions: states, actions, and reward signals.

Defines the observation space, action space, and reward function
for the multi-agent reinforcement learning defense engine.

State vector components:
    - risk_band:      0=low, 1=medium, 2=high
    - provider:       0=openai, 1=gemini, 2=ollama, 3=nvidia
    - hour_of_day:    0-23 (time-based threat patterns)
    - injection_hit:  0=no pattern match, 1=match
    - jailbreak_hit:  0=no pattern match, 1=match
    - cot_anomaly:    0=normal, 1=anomalous CoT detected

Actions:
    0 = ALLOW
    1 = RATE_LIMIT
    2 = QUARANTINE
    3 = ESCALATE
    4 = BLOCK
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import NamedTuple

from llm_wall.models import (
    AgentSignal,
    Provider,
    RiskBand,
    ThreatAction,
    ThreatCategory,
    ThreatReport,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NUM_AGENTS: int = 4          # One per defended layer
NUM_ACTIONS: int = 5         # allow, rate_limit, quarantine, escalate, block
STATE_DIMS: tuple[int, ...] = (3, 4, 24, 2, 2, 2)  # state space shape

ACTION_TO_THREAT: dict[int, ThreatAction] = {
    0: ThreatAction.ALLOW,
    1: ThreatAction.RATE_LIMIT,
    2: ThreatAction.QUARANTINE,
    3: ThreatAction.ESCALATE,
    4: ThreatAction.BLOCK,
}

THREAT_TO_ACTION: dict[ThreatAction, int] = {
    v: k for k, v in ACTION_TO_THREAT.items()
}

_PROVIDER_IDX: dict[Provider, int] = {
    Provider.OPENAI: 0,
    Provider.GEMINI: 1,
    Provider.OLLAMA: 2,
    Provider.NVIDIA: 3,
}

_BAND_IDX: dict[RiskBand, int] = {
    RiskBand.LOW: 0,
    RiskBand.MEDIUM: 1,
    RiskBand.HIGH: 2,
}


# ---------------------------------------------------------------------------
# State Encoding
# ---------------------------------------------------------------------------


class StateVector(NamedTuple):
    """Discrete state representation for the Q-table.

    Attributes:
        risk_band: 0=low, 1=medium, 2=high.
        provider: 0-3 mapping to Provider enum.
        hour_of_day: 0-23 UTC hour.
        injection_hit: 1 if injection pattern matched.
        jailbreak_hit: 1 if jailbreak pattern matched.
        cot_anomaly: 1 if CoT inspector found anomaly.
    """

    risk_band: int
    provider: int
    hour_of_day: int
    injection_hit: int
    jailbreak_hit: int
    cot_anomaly: int


def encode_state(report: ThreatReport, provider: Provider) -> StateVector:
    """Encodes a ThreatReport into a discrete StateVector for Q-lookup.

    Args:
        report: Aggregated ThreatReport from Guardian engine.
        provider: The LLM provider of the intercepted request.

    Returns:
        A StateVector tuple for Q-table lookup.
    """
    hour = datetime.now(timezone.utc).hour
    injection_hit = int(
        any(
            s.category
            in (
                ThreatCategory.PROMPT_INJECTION,
                ThreatCategory.TOOL_ABUSE,
            )
            for s in report.signals
            if s.score > 20
        )
    )
    jailbreak_hit = int(
        any(
            s.category == ThreatCategory.JAILBREAK
            for s in report.signals
            if s.score > 20
        )
    )
    cot_anomaly = int(
        any(
            s.agent_name == "cot_inspector" and s.score > 30
            for s in report.signals
        )
    )
    return StateVector(
        risk_band=_BAND_IDX.get(report.risk_band, 0),
        provider=_PROVIDER_IDX.get(provider, 0),
        hour_of_day=hour,
        injection_hit=injection_hit,
        jailbreak_hit=jailbreak_hit,
        cot_anomaly=cot_anomaly,
    )


# ---------------------------------------------------------------------------
# Reward Function
# ---------------------------------------------------------------------------


def compute_reward(
    action: int,
    actual_threat: bool,
    risk_score: int,
) -> float:
    """Computes the scalar reward for a taken action.

    Reward structure:
        +10  Blocked a confirmed attack (action=4, actual_threat=True)
        +5   Rate-limited or quarantined a real threat
        +2   Escalated a real threat to human review
        +1   Correctly allowed a benign request
        -5   False positive block (blocked a benign request)
        -3   False positive quarantine
        -10  Allowed a confirmed attack (missed detection)
        -2   Unnecessary escalation of benign request

    Args:
        action: Integer action index (0-4).
        actual_threat: True if the request was later confirmed malicious.
        risk_score: Numeric risk score 0-100.

    Returns:
        Float reward scalar.
    """
    if actual_threat:
        if action == 4:    # BLOCK
            return 10.0
        if action in (2, 3):  # QUARANTINE or ESCALATE
            return 5.0
        if action == 1:    # RATE_LIMIT
            return 3.0
        return -10.0       # ALLOW — missed attack
    else:
        if action == 0:    # ALLOW — correct
            return 1.0
        if action == 4:    # BLOCK — false positive
            return -5.0
        if action == 2:    # QUARANTINE — unnecessary
            return -3.0
        if action == 3:    # ESCALATE — unnecessary
            return -2.0
        if action == 1:    # RATE_LIMIT — minor false positive
            return -1.0
    return 0.0
