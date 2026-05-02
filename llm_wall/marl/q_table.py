# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Q-table implementation for tabular Q-learning.

Provides thread-safe read/write access to a multi-dimensional dict-backed
Q-table with JSON persistence. Designed for use by the MARL engine where
each of N agents maintains its own Q-table over shared (state, action) pairs.
"""

from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

import numpy as np

from llm_wall.config import get_settings
from llm_wall.marl.environment import NUM_ACTIONS, StateVector

logger = logging.getLogger(__name__)

# Sentinel value for uninitialised Q-entries.
_INITIAL_Q: float = 0.0


class QTable:
    """Thread-safe tabular Q-table for a single MARL agent.

    Stores Q(s, a) values as a nested defaultdict, keyed by the
    StateVector tuple. Persists to JSON on demand.

    Example:
        >>> qt = QTable(agent_id="gateway")
        >>> state = StateVector(2, 0, 14, 1, 0, 0)
        >>> qt.update(state, action=4, delta=3.0)
        >>> best = qt.best_action(state)
    """

    def __init__(
        self,
        agent_id: str,
        learning_rate: float | None = None,
        discount_factor: float | None = None,
        persist_path: str | None = None,
    ) -> None:
        """Initialises the Q-table with heuristic seeding.

        Args:
            agent_id: Unique identifier for this agent's table.
            learning_rate: Alpha (α) for Q-update; falls back to config.
            discount_factor: Gamma (γ) for Q-update; falls back to config.
            persist_path: JSON file for persistence; falls back to config.
        """
        cfg = get_settings()
        self._agent_id = agent_id
        self._alpha: float = learning_rate or cfg.marl_learning_rate
        self._gamma: float = discount_factor or cfg.marl_discount_factor
        self._lock = threading.RLock()
        # Q[state_tuple][action_index] → float
        self._table: dict[tuple[int, ...], list[float]] = defaultdict(
            lambda: [_INITIAL_Q] * NUM_ACTIONS
        )
        persist_base = Path(persist_path or cfg.marl_persist_path)
        self._persist_path: Path = persist_base.with_name(
            f"{persist_base.stem}_{agent_id}{persist_base.suffix}"
        )
        if self._persist_path.exists():
            self._load()
        else:
            self._seed_heuristic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_q(self, state: StateVector, action: int) -> float:
        """Returns the current Q-value for a (state, action) pair.

        Args:
            state: Encoded state vector.
            action: Integer action index (0 to NUM_ACTIONS-1).

        Returns:
            Float Q-value.
        """
        with self._lock:
            return self._table[tuple(state)][action]

    def best_action(self, state: StateVector) -> int:
        """Returns the greedy action with the highest Q-value.

        Args:
            state: Encoded state vector.

        Returns:
            Integer index of the best action.
        """
        with self._lock:
            values = self._table[tuple(state)]
            return int(np.argmax(values))

    def all_q_values(self, state: StateVector) -> list[float]:
        """Returns all Q-values for a given state.

        Args:
            state: Encoded state vector.

        Returns:
            List of Q-values indexed by action.
        """
        with self._lock:
            return list(self._table[tuple(state)])

    def update(
        self,
        state: StateVector,
        action: int,
        reward: float,
        next_state: StateVector | None = None,
    ) -> None:
        """Applies a Bellman Q-update in place.

        Q(s,a) ← Q(s,a) + α [r + γ max_a' Q(s',a') - Q(s,a)]

        Args:
            state: Current state at time of action.
            action: Action taken (integer index).
            reward: Scalar reward received.
            next_state: Next observed state (None for terminal states).
        """
        with self._lock:
            current_q = self._table[tuple(state)][action]
            if next_state is not None:
                max_next_q = max(self._table[tuple(next_state)])
            else:
                max_next_q = 0.0
            new_q = current_q + self._alpha * (
                reward + self._gamma * max_next_q - current_q
            )
            self._table[tuple(state)][action] = new_q
        logger.debug(
            "Q-update: agent=%s action=%d reward=%.2f q: %.3f→%.3f",
            self._agent_id,
            action,
            reward,
            current_q,
            new_q,
        )

    def persist(self) -> None:
        """Saves the Q-table to the configured JSON file."""
        self._persist_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            serialisable = {
                str(k): v for k, v in self._table.items()
            }
        with self._persist_path.open("w", encoding="utf-8") as fp:
            json.dump(
                {"agent_id": self._agent_id, "table": serialisable},
                fp,
                indent=2,
            )
        logger.debug(
            "Q-table persisted: agent=%s entries=%d",
            self._agent_id,
            len(serialisable),
        )

    def export_heatmap(self) -> list[dict[str, Any]]:
        """Exports the Q-table as a list suitable for dashboard rendering.

        Returns:
            List of dicts with 'state', 'action', and 'q_value' keys
            for the top-100 most visited (non-zero) entries.
        """
        rows: list[dict[str, Any]] = []
        with self._lock:
            for state_key, values in self._table.items():
                for action_idx, q_val in enumerate(values):
                    if abs(q_val) > 0.001:
                        rows.append(
                            {
                                "state": state_key,
                                "action": action_idx,
                                "q_value": round(q_val, 4),
                            }
                        )
        rows.sort(key=lambda r: abs(r["q_value"]), reverse=True)
        return rows[:100]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _seed_heuristic(self) -> None:
        """Seeds Q-table with domain-knowledge heuristics.

        Pre-warm the table so the system makes reasonable decisions
        from the very first request, before any online learning.
        """
        # For HIGH risk (band=2): strongly prefer BLOCK (action 4)
        for provider in range(4):
            for hour in range(24):
                state = (2, provider, hour, 1, 1, 1)
                self._table[state] = [
                    -5.0,   # ALLOW
                    2.0,    # RATE_LIMIT
                    4.0,    # QUARANTINE
                    3.0,    # ESCALATE
                    8.0,    # BLOCK
                ]
                # HIGH risk, single injection hit
                state2 = (2, provider, hour, 1, 0, 0)
                self._table[state2] = [
                    -3.0, 1.0, 3.0, 2.0, 6.0
                ]
        # For MEDIUM risk (band=1): prefer QUARANTINE
        for provider in range(4):
            for hour in range(24):
                state = (1, provider, hour, 0, 0, 0)
                self._table[state] = [
                    2.0,    # ALLOW
                    3.0,    # RATE_LIMIT
                    4.0,    # QUARANTINE
                    3.5,    # ESCALATE
                    1.0,    # BLOCK (too aggressive for medium)
                ]
        # For LOW risk (band=0): prefer ALLOW
        for provider in range(4):
            for hour in range(24):
                state = (0, provider, hour, 0, 0, 0)
                self._table[state] = [
                    5.0,    # ALLOW
                    1.0,    # RATE_LIMIT
                    -1.0,   # QUARANTINE
                    -2.0,   # ESCALATE
                    -5.0,   # BLOCK
                ]
        logger.info(
            "Q-table heuristic seeded for agent=%s", self._agent_id
        )

    def _load(self) -> None:
        """Loads a previously persisted Q-table from JSON."""
        with self._persist_path.open("r", encoding="utf-8") as fp:
            raw = json.load(fp)
        with self._lock:
            for key_str, values in raw.get("table", {}).items():
                key = tuple(int(x) for x in key_str.strip("()").split(", "))
                self._table[key] = values
        logger.info(
            "Q-table loaded: agent=%s entries=%d",
            self._agent_id,
            len(self._table),
        )
