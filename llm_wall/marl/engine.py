# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Multi-Agent Reinforcement Learning defense engine.

Orchestrates N defensive agents (one per protection layer), each with
its own Q-table and exploration policy. Agents share observations
but maintain independent value functions for decentralised control.

Defended layers:
    gateway   — outer proxy request filtering
    tool      — MCP tool-call gating
    context   — conversation context analysis
    escalate  — human review escalation decisions
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from llm_wall.marl.environment import (
    ACTION_TO_THREAT,
    NUM_AGENTS,
    StateVector,
    compute_reward,
    encode_state,
)
from llm_wall.marl.policies import EpsilonGreedyPolicy
from llm_wall.marl.q_table import QTable
from llm_wall.models import Provider, ThreatAction, ThreatReport

logger = logging.getLogger(__name__)

_AGENT_NAMES: list[str] = ["gateway", "tool", "context", "escalate"]


class MARLEngine:
    """Adaptive multi-agent defense engine using tabular Q-learning.

    Each agent independently decides an action for its defended layer.
    The final action is determined by a consensus vote with risk-weighted
    override for high-confidence blocks.

    Example:
        >>> engine = MARLEngine()
        >>> action = await engine.decide(threat_report, Provider.OLLAMA)
        >>> engine.record_outcome(state, action, actual_threat=True)
    """

    def __init__(self) -> None:
        """Initialises Q-tables and policies for all defensive agents."""
        self._agents: dict[str, QTable] = {
            name: QTable(agent_id=name) for name in _AGENT_NAMES
        }
        self._policies: dict[str, EpsilonGreedyPolicy] = {
            name: EpsilonGreedyPolicy() for name in _AGENT_NAMES
        }
        self._last_states: dict[str, StateVector | None] = {
            name: None for name in _AGENT_NAMES
        }
        self._last_actions: dict[str, int | None] = {
            name: None for name in _AGENT_NAMES
        }
        self._decision_count: int = 0
        logger.info("MARL engine initialised with %d agents.", NUM_AGENTS)

    async def decide(
        self,
        report: ThreatReport,
        provider: Provider,
    ) -> ThreatAction:
        """Computes the consensus defensive action for a threat report.

        All agents observe the same encoded state and independently vote.
        Votes are tallied; if any agent votes BLOCK with HIGH risk,
        that overrides the vote (risk-weighted veto).

        Args:
            report: Guardian threat report with risk score and signals.
            provider: LLM provider of the intercepted request.

        Returns:
            Consensus ThreatAction to execute.
        """
        state = encode_state(report, provider)
        votes: list[int] = []

        for name in _AGENT_NAMES:
            qtable = self._agents[name]
            policy = self._policies[name]
            action_idx = policy.select_action(qtable, state)
            votes.append(action_idx)
            self._last_states[name] = state
            self._last_actions[name] = action_idx
            logger.debug(
                "MARL agent=%s state=%s vote=%s epsilon=%.3f",
                name,
                state,
                ACTION_TO_THREAT[action_idx].value,
                policy.epsilon,
            )

        self._decision_count += 1

        # Risk-weighted veto: if risk_band==HIGH and any agent votes BLOCK
        if state.risk_band == 2 and 4 in votes:
            logger.info(
                "MARL veto: HIGH risk + BLOCK vote → BLOCK (request #%d)",
                self._decision_count,
            )
            return ThreatAction.BLOCK

        # Majority vote
        consensus_action = max(set(votes), key=votes.count)
        action = ACTION_TO_THREAT[consensus_action]
        logger.info(
            "MARL decision #%d: votes=%s → %s",
            self._decision_count,
            [ACTION_TO_THREAT[v].value for v in votes],
            action.value,
        )
        return action

    def record_outcome(
        self,
        state: StateVector,
        action: ThreatAction,
        actual_threat: bool,
        risk_score: int = 50,
    ) -> None:
        """Records the outcome of a decision for online Q-learning.

        Should be called asynchronously after ground-truth is known
        (e.g., from analyst feedback or honeypot confirmation).

        Args:
            state: The state at time of the decision.
            action: The ThreatAction that was executed.
            actual_threat: True if the request was confirmed malicious.
            risk_score: Numeric risk score for reward computation.
        """
        from llm_wall.marl.environment import (  # pylint: disable=import-outside-toplevel
            THREAT_TO_ACTION,
            compute_reward,
        )

        action_idx = THREAT_TO_ACTION.get(action, 0)
        reward = compute_reward(action_idx, actual_threat, risk_score)

        for name in _AGENT_NAMES:
            self._agents[name].update(
                state=state,
                action=action_idx,
                reward=reward,
                next_state=None,  # terminal for this episode
            )
        logger.info(
            "MARL outcome recorded: action=%s threat=%s reward=%.2f",
            action.value,
            actual_threat,
            reward,
        )

    def persist_all(self) -> None:
        """Persists all agent Q-tables to disk."""
        for agent in self._agents.values():
            agent.persist()
        logger.info("All MARL Q-tables persisted.")

    def get_status(self) -> dict[str, Any]:
        """Returns a status snapshot for the dashboard.

        Returns:
            Dict with agent names, epsilons, and decision count.
        """
        return {
            "decision_count": self._decision_count,
            "agents": [
                {
                    "name": name,
                    "epsilon": round(
                        self._policies[name].epsilon, 4
                    ),
                    "q_entries": len(
                        self._agents[name]._table  # pylint: disable=protected-access
                    ),
                }
                for name in _AGENT_NAMES
            ],
        }

    def get_heatmap(self, agent_name: str) -> list[dict[str, Any]]:
        """Returns Q-table heatmap data for a specific agent.

        Args:
            agent_name: One of 'gateway', 'tool', 'context', 'escalate'.

        Returns:
            List of heatmap rows from QTable.export_heatmap().

        Raises:
            KeyError: If agent_name is invalid.
        """
        return self._agents[agent_name].export_heatmap()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: MARLEngine | None = None


def get_marl_engine() -> MARLEngine:
    """Returns the singleton MARLEngine instance.

    Returns:
        Global MARLEngine singleton.
    """
    global _engine_instance  # pylint: disable=global-statement
    if _engine_instance is None:
        _engine_instance = MARLEngine()
    return _engine_instance
