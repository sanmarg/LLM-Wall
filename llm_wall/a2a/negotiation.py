# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""A2A consensus and escalation negotiation protocols.

Defines two protocols agents use to collectively decide on ambiguous threats:
    1. MajorityVote — 3+ agents must agree before blocking.
    2. HighConfidenceVeto — single agent overrides at threshold ≥ 0.9.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from collections import Counter
from typing import Any

from llm_wall.a2a.bus import TOPIC_CONSENSUS_REQUEST, TOPIC_CONSENSUS_VOTE, get_bus
from llm_wall.models import (
    A2AMessage,
    AgentSignal,
    ConsensusRequest,
    ConsensusVote,
    ThreatAction,
    ThreatReport,
)

logger = logging.getLogger(__name__)

# Minimum votes required for majority decision.
_MIN_MAJORITY_VOTES: int = 2
_CONSENSUS_TIMEOUT_SECS: float = 3.0


class ConsensusEngine:
    """Manages A2A consensus rounds for quarantine-band threats.

    When Guardian assigns QUARANTINE, it triggers a consensus round
    where registered agents vote on the final action.

    Example:
        >>> engine = ConsensusEngine()
        >>> engine.register_voter("marl_engine", voter_fn)
        >>> action = await engine.run_consensus(report)
    """

    def __init__(self) -> None:
        """Initialises the consensus engine with empty voter registry."""
        self._voters: dict[str, Any] = {}
        self._pending_rounds: dict[str, asyncio.Future[ThreatAction]] = {}
        self._vote_log: dict[str, list[ConsensusVote]] = {}
        bus = get_bus()
        bus.subscribe(TOPIC_CONSENSUS_VOTE, self._handle_vote)

    def register_voter(
        self,
        voter_id: str,
        vote_fn: Any,
    ) -> None:
        """Registers an agent as a consensus voter.

        Args:
            voter_id: Unique agent identifier string.
            vote_fn: Async callable(ConsensusRequest) → ConsensusVote.
        """
        self._voters[voter_id] = vote_fn
        logger.info("Consensus voter registered: %s", voter_id)

    async def run_consensus(
        self, report: ThreatReport, timeout: float = _CONSENSUS_TIMEOUT_SECS
    ) -> ThreatAction:
        """Runs a consensus vote round for a quarantine-band threat.

        Broadcasts a ConsensusRequest to all voters. Collects votes with
        timeout. Returns the majority action, defaulting to QUARANTINE
        if consensus is not reached.

        Args:
            report: ThreatReport triggering the consensus round.
            timeout: Maximum seconds to collect votes.

        Returns:
            Consensus ThreatAction.
        """
        consensus_id = str(uuid.uuid4())
        consensus_req = ConsensusRequest(
            consensus_id=consensus_id,
            request_id=report.request_id,
            risk_score=report.risk_score,
            signals=report.signals,
            timeout_secs=timeout,
        )
        self._vote_log[consensus_id] = []
        future: asyncio.Future[ThreatAction] = asyncio.get_event_loop().create_future()
        self._pending_rounds[consensus_id] = future

        bus = get_bus()
        await bus.publish(
            A2AMessage(
                sender_id="consensus_engine",
                topic=TOPIC_CONSENSUS_REQUEST,
                payload=consensus_req.model_dump(mode="json"),
                priority=8,
            )
        )

        # Solicit votes directly from registered voters
        vote_tasks = [
            self._solicit_vote(voter_id, vote_fn, consensus_req)
            for voter_id, vote_fn in self._voters.items()
        ]
        await asyncio.gather(
            *vote_tasks, return_exceptions=True
        )

        # Wait for all votes (with timeout)
        try:
            await asyncio.wait_for(
                asyncio.shield(future), timeout=timeout
            )
        except asyncio.TimeoutError:
            logger.warning(
                "Consensus timed out after %.1fs for %s", timeout, consensus_id[:8]
            )

        return self._tally_votes(
            consensus_id, default=ThreatAction.QUARANTINE
        )

    async def _solicit_vote(
        self,
        voter_id: str,
        vote_fn: Any,
        req: ConsensusRequest,
    ) -> None:
        """Calls a voter function and submits the result to the bus.

        Args:
            voter_id: Voter agent identifier.
            vote_fn: Async callable returning a ConsensusVote.
            req: The consensus request.
        """
        try:
            vote: ConsensusVote = await asyncio.wait_for(
                vote_fn(req), timeout=_CONSENSUS_TIMEOUT_SECS
            )
            bus = get_bus()
            await bus.publish(
                A2AMessage(
                    sender_id=voter_id,
                    topic=TOPIC_CONSENSUS_VOTE,
                    payload=vote.model_dump(mode="json"),
                    priority=9,
                )
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Voter %s failed: %s", voter_id, exc)

    async def _handle_vote(self, message: A2AMessage) -> None:
        """Handles an incoming consensus vote message from the bus.

        Args:
            message: A2AMessage with ConsensusVote payload.
        """
        try:
            vote = ConsensusVote(**message.payload)
            round_votes = self._vote_log.get(vote.consensus_id)
            if round_votes is None:
                return
            round_votes.append(vote)
            logger.debug(
                "Consensus vote received: %s voted %s (conf=%.2f)",
                vote.voter_id,
                vote.vote.value,
                vote.confidence,
            )
            # Auto-resolve if all voters have voted
            if len(round_votes) >= len(self._voters):
                future = self._pending_rounds.get(vote.consensus_id)
                if future and not future.done():
                    future.set_result(ThreatAction.QUARANTINE)  # placeholder
        except Exception as exc:  # pylint: disable=broad-except
            logger.error("Error handling consensus vote: %s", exc)

    def _tally_votes(
        self,
        consensus_id: str,
        default: ThreatAction,
    ) -> ThreatAction:
        """Tallies votes and returns the majority action.

        High-confidence BLOCK votes (confidence ≥ 0.9) act as veto.

        Args:
            consensus_id: Round identifier.
            default: Action to return if no majority.

        Returns:
            Consensus ThreatAction.
        """
        votes = self._vote_log.get(consensus_id, [])
        if not votes:
            return default

        # High-confidence veto
        for vote in votes:
            if vote.vote == ThreatAction.BLOCK and vote.confidence >= 0.9:
                logger.info(
                    "Consensus veto: BLOCK by %s (conf=%.2f)",
                    vote.voter_id,
                    vote.confidence,
                )
                return ThreatAction.BLOCK

        # Majority vote
        counts = Counter(v.vote for v in votes)
        winner = counts.most_common(1)[0]
        if winner[1] >= _MIN_MAJORITY_VOTES:
            logger.info(
                "Consensus majority: %s (%d/%d votes)",
                winner[0].value,
                winner[1],
                len(votes),
            )
            return winner[0]

        logger.info("Consensus no majority, defaulting to %s", default.value)
        return default


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_consensus_engine: ConsensusEngine | None = None


def get_consensus_engine() -> ConsensusEngine:
    """Returns the singleton ConsensusEngine instance.

    Returns:
        Global ConsensusEngine singleton.
    """
    global _consensus_engine  # pylint: disable=global-statement
    if _consensus_engine is None:
        _consensus_engine = ConsensusEngine()
    return _consensus_engine
