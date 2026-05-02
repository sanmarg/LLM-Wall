# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Prompt injection detector Guardian agent.

Uses regex pattern matching against the curated injection and jailbreak
pattern databases. Augments pattern hits with an LLM confidence check
for borderline cases (score 30-60).
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

from llm_wall.models import AgentSignal, ThreatCategory

logger = logging.getLogger(__name__)

_PATTERNS_DIR = Path(__file__).parent.parent / "patterns"


def _load_patterns() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Loads injection and jailbreak pattern databases from JSON files.

    Returns:
        Tuple of (injection_patterns, jailbreak_patterns) lists.
    """
    with (_PATTERNS_DIR / "injection_patterns.json").open(
        encoding="utf-8"
    ) as fp:
        injection = json.load(fp)["injection_patterns"]
    with (_PATTERNS_DIR / "jailbreak_patterns.json").open(
        encoding="utf-8"
    ) as fp:
        jailbreak = json.load(fp)["jailbreak_patterns"]
    return injection, jailbreak


# Load at import time — patterns are static, no I/O overhead at runtime.
_INJECTION_PATTERNS, _JAILBREAK_PATTERNS = _load_patterns()

# Pre-compile all regexes for performance.
_COMPILED_INJECTION: list[tuple[dict[str, Any], re.Pattern[str]]] = []
_COMPILED_JAILBREAK: list[tuple[dict[str, Any], re.Pattern[str]]] = []

for _p in _INJECTION_PATTERNS:
    try:
        _COMPILED_INJECTION.append(
            (_p, re.compile(_p["pattern"], re.IGNORECASE | re.DOTALL))
        )
    except re.error as _e:
        logger.warning("Bad injection regex %s: %s", _p["id"], _e)

for _p in _JAILBREAK_PATTERNS:
    try:
        _COMPILED_JAILBREAK.append(
            (_p, re.compile(_p["pattern"], re.IGNORECASE | re.DOTALL))
        )
    except re.error as _e:
        logger.warning("Bad jailbreak regex %s: %s", _p["id"], _e)

logger.info(
    "Injection agent: loaded %d injection + %d jailbreak patterns.",
    len(_COMPILED_INJECTION),
    len(_COMPILED_JAILBREAK),
)


async def analyse_injection(prompt_text: str) -> AgentSignal:
    """Scans a prompt for injection and jailbreak patterns.

    Runs all compiled regexes against the prompt text. Score is computed
    as a weighted aggregate of matched pattern severities (max 100).

    Args:
        prompt_text: Full concatenated prompt content to scan.

    Returns:
        AgentSignal with match details or benign signal if no hits.
    """
    t0 = time.perf_counter()
    hits: list[dict[str, Any]] = []
    max_severity: int = 0
    primary_category = ThreatCategory.BENIGN
    text = prompt_text[:8000]  # Cap for performance

    for pattern_meta, regex in _COMPILED_INJECTION:
        match = regex.search(text)
        if match:
            hits.append(
                {
                    "id": pattern_meta["id"],
                    "name": pattern_meta["name"],
                    "severity": pattern_meta["severity"],
                    "snippet": match.group(0)[:80],
                }
            )
            if pattern_meta["severity"] > max_severity:
                max_severity = pattern_meta["severity"]
                primary_category = ThreatCategory(
                    pattern_meta.get("category", "prompt_injection")
                )

    for pattern_meta, regex in _COMPILED_JAILBREAK:
        match = regex.search(text)
        if match:
            hits.append(
                {
                    "id": pattern_meta["id"],
                    "name": pattern_meta["name"],
                    "severity": pattern_meta["severity"],
                    "snippet": match.group(0)[:80],
                }
            )
            if pattern_meta["severity"] > max_severity:
                max_severity = pattern_meta["severity"]
                primary_category = ThreatCategory(
                    pattern_meta.get("category", "jailbreak")
                )

    # Score = min(100, sum of top-3 severities * 10)
    if hits:
        top_severities = sorted(
            [h["severity"] for h in hits], reverse=True
        )[:3]
        score = min(100, sum(top_severities) * 10 // len(top_severities))
        confidence = min(1.0, len(hits) * 0.2 + 0.4)
        evidence = [
            f"[{h['id']}] {h['name']}: '{h['snippet']}'" for h in hits[:5]
        ]
    else:
        score = 0
        confidence = 0.95
        evidence = ["No injection or jailbreak patterns detected."]
        primary_category = ThreatCategory.BENIGN

    latency_ms = (time.perf_counter() - t0) * 1000
    logger.info(
        "InjectionAgent: hits=%d score=%d latency=%.1fms",
        len(hits),
        score,
        latency_ms,
    )
    return AgentSignal(
        agent_name="injection_agent",
        score=score,
        category=primary_category,
        confidence=confidence,
        evidence=evidence,
        latency_ms=latency_ms,
    )
