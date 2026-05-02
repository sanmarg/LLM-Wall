# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Guardian engine: orchestrates multi-agent threat analysis.

Runs all Guardian agents concurrently and aggregates their signals
into a ThreatReport. Integrates with the Sentinel IOC store for
real-time pattern matching against known indicators.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from llm_wall.config import get_settings
from llm_wall.guardian.agents.cot_inspector import analyse_cot
from llm_wall.guardian.agents.fidelity_agent import analyze_fidelity
from llm_wall.guardian.agents.injection_agent import analyse_injection
from llm_wall.guardian.agents.intent_agent import analyse_intent
from llm_wall.guardian.agents.risk_scorer import (
    build_explanation,
    compute_risk_score,
    determine_primary_category,
)
from llm_wall.models import (
    AgentSignal,
    LLMRequest,
    RiskBand,
    ThreatAction,
    ThreatCategory,
    ThreatReport,
)

logger = logging.getLogger(__name__)


class GuardianEngine:
    """Orchestrates the multi-agent threat analysis pipeline.

    Runs agents in parallel (or sequentially in safe-mode) and
    integrates Sentinel IOC hits as an additional signal.

    Example:
        >>> engine = GuardianEngine()
        >>> report = await engine.analyse(llm_request)
        >>> if report.action == ThreatAction.BLOCK:
        ...     return block_response(report)
    """

    def __init__(self, ioc_store: Any | None = None) -> None:
        """Initialises the Guardian engine.

        Args:
            ioc_store: Optional IOCStore for real-time IOC matching.
                       If None, IOC check is skipped.
        """
        self._cfg = get_settings()
        self._ioc_store = ioc_store
        logger.info(
            "GuardianEngine initialised: parallel=%s provider=%s",
            self._cfg.guardian_parallel_agents,
            self._cfg.guardian_analysis_provider,
        )

    async def analyse(self, request: LLMRequest) -> ThreatReport:
        """Runs all Guardian agents and returns a consolidated ThreatReport.

        Args:
            request: The normalised LLM request to analyse.

        Returns:
            ThreatReport with risk score, action, and per-agent signals.
        """
        t0 = time.perf_counter()
        prompt_text = request.full_prompt
        signals: list[AgentSignal] = []

        # Hard-coded safety floor for local development (bypasses config sync issues)
        timeout = 60.0

        if self._cfg.guardian_parallel_agents:
            signals = await self._run_parallel(
                request, timeout
            )
        else:
            signals = await self._run_sequential(
                request, timeout
            )

        # IOC store check
        if self._ioc_store is not None:
            ioc_signal = self._check_ioc_store(prompt_text)
            if ioc_signal is not None:
                signals.append(ioc_signal)

        risk_score = compute_risk_score(signals)
        primary_category = determine_primary_category(signals)
        risk_band = RiskBand.from_score(risk_score)
        action = self._determine_action(risk_score, signals)
        explanation = build_explanation(risk_score, signals, primary_category)
        processing_ms = (time.perf_counter() - t0) * 1000

        report = ThreatReport(
            request_id=request.request_id,
            risk_score=risk_score,
            risk_band=risk_band,
            action=action,
            primary_category=primary_category,
            signals=signals,
            explanation=explanation,
            processing_ms=processing_ms,
        )

        logger.info(
            "Guardian analysis: request=%s score=%d action=%s time=%.1fms",
            request.request_id[:8],
            risk_score,
            action.value,
            processing_ms,
        )
        return report

    async def _run_parallel(
        self,
        request: LLMRequest,
        timeout: float,
    ) -> list[AgentSignal]:
        """Runs all agents concurrently with a shared timeout."""
        prompt_text = request.full_prompt
        messages = request.messages

        tasks = [
            asyncio.wait_for(analyse_intent(prompt_text), timeout=timeout),
            asyncio.wait_for(analyse_injection(prompt_text), timeout=timeout),
            asyncio.wait_for(analyse_cot(messages), timeout=timeout),
            asyncio.wait_for(analyze_fidelity(request), timeout=timeout),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        signals: list[AgentSignal] = []
        names = ["intent_agent", "injection_agent", "cot_inspector", "fidelity_agent"]
        for name, result in zip(names, results):
            if isinstance(result, AgentSignal):
                signals.append(result)
            else:
                logger.warning(
                    "Agent %s failed or timed out: %s", name, result
                )
                signals.append(
                    AgentSignal(
                        agent_name=name,
                        score=50,
                        category=ThreatCategory.IOC_MATCH,
                        confidence=0.5,
                        evidence=[f"Agent reliability failure: {result}. Forced caution applied."],
                    )
                )
        return signals

    async def _run_sequential(
        self,
        request: LLMRequest,
        timeout: float,
    ) -> list[AgentSignal]:
        """Runs agents sequentially (safe fallback mode).

        Args:
            request: The LLM request.
            timeout: Per-agent timeout in seconds.

        Returns:
            List of AgentSignal objects.
        """
        prompt_text = request.full_prompt
        messages = request.messages

        signals: list[AgentSignal] = []
        for coro, name in [
            (analyse_intent(prompt_text), "intent_agent"),
            (analyse_injection(prompt_text), "injection_agent"),
            (analyse_cot(messages), "cot_inspector"),
            (analyze_fidelity(request), "fidelity_agent"),
        ]:
            try:
                signal = await asyncio.wait_for(coro, timeout=timeout)
                signals.append(signal)
            except Exception as exc:  # pylint: disable=broad-except
                logger.warning("Agent %s failed: %s", name, exc)
                signals.append(
                    AgentSignal(
                        agent_name=name,
                        score=10,
                        category=ThreatCategory.BENIGN,
                        confidence=0.1,
                        evidence=[f"Agent error: {exc}"],
                    )
                )
        return signals

    def _check_ioc_store(self, prompt_text: str) -> AgentSignal | None:
        """Checks prompt against the Sentinel IOC store.

        Args:
            prompt_text: Full prompt text.

        Returns:
            AgentSignal if IOC matches found, None otherwise.
        """
        matches = self._ioc_store.match(prompt_text)
        if not matches:
            return None
        top = matches[0]
        score = min(100, top.severity * 10)
        logger.info(
            "IOC match: pattern='%s' severity=%d score=%d",
            top.pattern[:40],
            top.severity,
            score,
        )
        return AgentSignal(
            agent_name="ioc_matcher",
            score=score,
            category=top.category,
            confidence=0.9,
            evidence=[
                f"IOC match [{top.ioc_id[:8]}]: '{top.pattern[:60]}' "
                f"(severity={top.severity}, hits={top.hit_count})"
            ],
        )

    def _determine_action(
        self,
        risk_score: int,
        signals: list[AgentSignal],
    ) -> ThreatAction:
        """Maps risk score and signals to a ThreatAction.

        Args:
            risk_score: Aggregated 0-100 risk score.
            signals: All agent signals (used for override checks).

        Returns:
            ThreatAction enum value.
        """
        block_threshold = self._cfg.guardian_risk_threshold_block
        quarantine_threshold = self._cfg.guardian_risk_threshold_quarantine

        # Hard block for tool-abuse or LLMjacking regardless of score
        for sig in signals:
            if (
                sig.category in (
                    ThreatCategory.TOOL_ABUSE, ThreatCategory.LLMJACKING
                )
                and sig.confidence >= 0.7
                and sig.score >= 60
            ):
                logger.warning(
                    "Hard block override: category=%s score=%d",
                    sig.category.value,
                    sig.score,
                )
                return ThreatAction.BLOCK

        if risk_score >= block_threshold:
            return ThreatAction.BLOCK
        if risk_score >= quarantine_threshold:
            return ThreatAction.QUARANTINE
        if risk_score >= 20:
            return ThreatAction.RATE_LIMIT
        return ThreatAction.ALLOW


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_guardian_instance: GuardianEngine | None = None


def get_guardian_engine(ioc_store: Any | None = None) -> GuardianEngine:
    """Returns the singleton GuardianEngine instance.

    Args:
        ioc_store: Optional IOCStore; only used on first call.

    Returns:
        Global GuardianEngine singleton.
    """
    global _guardian_instance  # pylint: disable=global-statement
    if _guardian_instance is None:
        _guardian_instance = GuardianEngine(ioc_store=ioc_store)
    return _guardian_instance
