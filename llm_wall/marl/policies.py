# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Epsilon-greedy and UCB exploration policies for the MARL engine."""

from __future__ import annotations

import logging
import math
import random
from collections import defaultdict

from llm_wall.config import get_settings
from llm_wall.marl.environment import NUM_ACTIONS
from llm_wall.marl.q_table import QTable
from llm_wall.marl.environment import StateVector

logger = logging.getLogger(__name__)


class EpsilonGreedyPolicy:
    """Epsilon-greedy action selection with exponential decay.

    Balances exploration vs. exploitation. Epsilon decays towards
    ``epsilon_min`` after every call to ``select_action``.

    Example:
        >>> policy = EpsilonGreedyPolicy()
        >>> action = policy.select_action(q_table, state)
    """

    def __init__(
        self,
        epsilon: float | None = None,
        epsilon_decay: float | None = None,
        epsilon_min: float | None = None,
    ) -> None:
        """Initialises policy parameters from config.

        Args:
            epsilon: Initial exploration probability.
            epsilon_decay: Multiplicative decay per step.
            epsilon_min: Floor on exploration probability.
        """
        cfg = get_settings()
        self.epsilon: float = epsilon or cfg.marl_epsilon
        self._decay: float = epsilon_decay or cfg.marl_epsilon_decay
        self._min: float = epsilon_min or cfg.marl_epsilon_min
        self._step_count: int = 0

    def select_action(
        self,
        q_table: "QTable",
        state: "StateVector",
    ) -> int:
        """Selects an action using epsilon-greedy exploration.

        Args:
            q_table: The agent's Q-table for greedy lookup.
            state: Current encoded state vector.

        Returns:
            Integer action index.
        """
        self._step_count += 1
        if random.random() < self.epsilon:
            action = random.randrange(NUM_ACTIONS)
            logger.debug(
                "Explore: step=%d epsilon=%.3f action=%d",
                self._step_count,
                self.epsilon,
                action,
            )
        else:
            action = q_table.best_action(state)
            logger.debug(
                "Exploit: step=%d action=%d", self._step_count, action
            )
        # Decay epsilon
        self.epsilon = max(self._min, self.epsilon * self._decay)
        return action


class UCBPolicy:
    """Upper Confidence Bound (UCB1) action selection.

    Provides optimistic exploration by selecting actions with the
    highest upper confidence bound on Q-value estimates.

    Reference: Auer et al., 2002 — "Finite-time Analysis of the
    Multiarmed Bandit Problem".
    """

    def __init__(self, c: float = 2.0) -> None:
        """Initialises the UCB policy.

        Args:
            c: Exploration constant (higher = more exploration).
        """
        self._c: float = c
        self._action_counts: dict[tuple[int, ...], list[int]] = defaultdict(
            lambda: [1] * NUM_ACTIONS  # Start at 1 to avoid log(0)
        )
        self._total_counts: dict[tuple[int, ...], int] = defaultdict(
            lambda: NUM_ACTIONS
        )

    def select_action(
        self,
        q_table: "QTable",
        state: "StateVector",
    ) -> int:
        """Selects action with the highest UCB1 value.

        Args:
            q_table: The agent's Q-table for value estimates.
            state: Current encoded state vector.

        Returns:
            Integer action index.
        """
        state_key = tuple(state)
        total_n = self._total_counts[state_key]
        q_values = q_table.all_q_values(state)
        counts = self._action_counts[state_key]

        ucb_values = [
            q + self._c * math.sqrt(math.log(total_n) / n)
            for q, n in zip(q_values, counts)
        ]
        action = int(max(range(NUM_ACTIONS), key=lambda i: ucb_values[i]))

        self._action_counts[state_key][action] += 1
        self._total_counts[state_key] += 1
        return action
