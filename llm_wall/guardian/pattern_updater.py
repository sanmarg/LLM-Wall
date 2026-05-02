# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Automatic pattern update and evolution engine for the Guardian.

This module pulls threat intelligence from public sources, evolves
patterns from blocked-request feedback, and hot-reloads them into
the injection agent — all without requiring a restart.

Sources supported:
    1. Remote JSON feeds (GitHub raw, custom threat-intel APIs)
    2. MARL/Guardian feedback loop — prompts that scored high but
       slipped through evolve into new regex patterns via LLM synthesis
    3. IOC store aggregation — high-hit IOC patterns promoted to the
       canonical pattern DB

Pattern lifecycle:
    fetch → validate_regex → score → deduplicate → persist → hot_reload
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from llm_wall.config import get_settings
from llm_wall.guardian.llm_clients import call_analysis_llm

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Known public threat-intelligence pattern feeds
# ---------------------------------------------------------------------------

_PUBLIC_FEEDS: list[dict[str, Any]] = [
    {
        "name": "AdvBench Live (Harmful Behaviors)",
        "url": (
            "https://raw.githubusercontent.com/llm-attacks/llm-attacks"
            "/main/data/advbench/harmful_behaviors.csv"
        ),
        "format": "csv",
        "category": "jailbreak",
        "severity": 8,
    },
    {
        "name": "HuggingFace Cybertron (Prompt Injections)",
        "url": (
            "https://huggingface.co/datasets/fka/prompts.chat"
            "/resolve/main/prompts.csv"
        ),
        "format": "csv",
        "category": "prompt_injection",
        "severity": 7,
    },
    {
        "name": "JailbreakBench Production (Official)",
        "url": (
            "https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors"
            "/resolve/main/data/harmful-behaviors.csv"
        ),
        "format": "csv",
        "category": "jailbreak",
        "severity": 9,
    },
]

# Internal Sentinel Mesh feed (Self-evolving Feed)
_SENTINEL_FEED_NAME = "Sentinel Mesh Internal"

# Where evolved patterns are persisted (separate from built-in patterns).
_EVOLVED_PATTERNS_FILE = Path(
    get_settings().data_dir / "evolved_patterns.json"
)

# LLM synthesis prompt for new pattern generation.
_SYNTHESIS_SCHEMA = """
Respond with exactly this JSON schema — an array of objects:
[
  {
    "id": "EVO-<3 digit number>",
    "name": "<short descriptive name>",
    "pattern": "<Python regex pattern, case-insensitive>",
    "severity": <integer 1-10>,
    "category": "<prompt_injection|jailbreak|goal_hijacking|data_exfiltration|tool_abuse|llmjacking>"
  }
]
Generate at most 5 patterns. Patterns must be valid Python regex.
"""


def _compute_pattern_hash(pattern: str) -> str:
    """Computes a short hash for deduplication.

    Args:
        pattern: Regex pattern string.

    Returns:
        8-character hex hash.
    """
    return hashlib.md5(pattern.lower().strip().encode()).hexdigest()[:8]


def _validate_regex(pattern: str) -> bool:
    """Tests whether a pattern string is a valid Python regex.

    Args:
        pattern: Candidate regex string.

    Returns:
        True if valid, False otherwise.
    """
    try:
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
        return True
    except re.error:
        return False


def _load_evolved_patterns() -> dict[str, Any]:
    """Loads the evolved pattern database from disk.

    Returns:
        Dict with 'patterns' list and 'metadata' dict.
    """
    if not _EVOLVED_PATTERNS_FILE.exists():
        return {
            "metadata": {
                "last_updated": None,
                "total_patterns": 0,
                "sources": [],
            },
            "patterns": [],
        }
    with _EVOLVED_PATTERNS_FILE.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def _save_evolved_patterns(data: dict[str, Any]) -> None:
    """Persists the evolved pattern database to disk.

    Args:
        data: Pattern dict to persist.
    """
    _EVOLVED_PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    data["metadata"]["total_patterns"] = len(data["patterns"])
    with _EVOLVED_PATTERNS_FILE.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)


def get_all_evolved_patterns() -> list[dict[str, Any]]:
    """Returns all currently evolved patterns.

    Returns:
        List of pattern dicts with id, name, pattern, severity, category.
    """
    return _load_evolved_patterns().get("patterns", [])


# ---------------------------------------------------------------------------
# Feed parsers
# ---------------------------------------------------------------------------


def _parse_csv_feed(text: str, category: str, severity: int) -> list[str]:
    """Extracts prompt strings from a CSV feed (first column used).

    Args:
        text: Raw CSV content.
        category: Threat category for these patterns.
        severity: Base severity score.

    Returns:
        List of raw prompt strings.
    """
    lines = text.strip().splitlines()
    prompts: list[str] = []
    for line in lines[1:50]:  # Skip header, limit to 50
        # CSV: take first column, strip quotes
        first_col = line.split(",")[0].strip().strip('"').strip("'")
        if len(first_col) > 20:
            prompts.append(first_col[:200])
    return prompts


def _parse_python_list_feed(text: str) -> list[str]:
    """Extracts string literals from a Python list source file.

    Args:
        text: Raw Python source with string literals.

    Returns:
        List of extracted string literals.
    """
    pattern = re.compile(r'"([^"]{10,150})"')
    return pattern.findall(text)[:50]


async def _fetch_feed(
    feed: dict[str, Any],
    client: httpx.AsyncClient,
) -> list[str]:
    """Fetches and parses a single threat-intel feed.

    Args:
        feed: Feed metadata dict with url, format, category etc.
        client: Shared async HTTP client.

    Returns:
        List of raw extracted strings (prompts / patterns).
    """
    try:
        resp = await client.get(feed["url"], timeout=15.0, follow_redirects=True)
        resp.raise_for_status()
        text = resp.text

        if feed["format"] == "csv":
            return _parse_csv_feed(text, feed["category"], feed["severity"])
        if feed["format"] == "python_list":
            return _parse_python_list_feed(text)
        # Default: line-by-line
        return [
            line.strip() for line in text.splitlines()
            if len(line.strip()) > 15
        ][:50]
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "Feed fetch failed: %s → %s", feed["name"], exc
        )
        return []


# ---------------------------------------------------------------------------
# Pattern synthesis via LLM
# ---------------------------------------------------------------------------


async def synthesise_patterns_from_prompts(
    raw_prompts: list[str],
    feed_name: str,
) -> list[dict[str, Any]]:
    """Uses the Guardian LLM to synthesise regex patterns from raw prompts.

    Args:
        raw_prompts: List of adversarial prompt strings from a feed.
        feed_name: Human-readable source name for logging.

    Returns:
        List of validated pattern dicts.
    """
    if not raw_prompts:
        return []

    sample = "\n".join(f"- {p[:120]}" for p in raw_prompts[:10])
    synthesis_prompt = (
        f"You are a security regex engineer. I will give you a list of "
        f"adversarial AI prompts from the '{feed_name}' dataset. "
        f"Synthesise generalised Python regex patterns that would detect "
        f"these types of attack, without being too broad (avoid patterns "
        f"that match benign text).\n\n"
        f"Sample prompts:\n{sample}"
    )

    try:
        result = await call_analysis_llm(synthesis_prompt, _SYNTHESIS_SCHEMA)
        patterns: list[dict[str, Any]] = []

        # Handle both top-level list and wrapped dict
        raw_list = result if isinstance(result, list) else result.get("patterns", [])

        for item in raw_list:
            pat = item.get("pattern", "")
            if not pat or not _validate_regex(pat):
                logger.debug("Skipping invalid regex from LLM: %s", pat[:60])
                continue
            item["source"] = feed_name
            item["auto_generated"] = True
            item["hash"] = _compute_pattern_hash(pat)
            patterns.append(item)

        logger.info(
            "LLM synthesised %d patterns from '%s'", len(patterns), feed_name
        )
        return patterns

    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "Pattern synthesis failed for '%s': %s", feed_name, exc
        )
        return []


# ---------------------------------------------------------------------------
# IOC promotion (Sentinel → Pattern DB)
# ---------------------------------------------------------------------------


def promote_ioc_patterns(ioc_store: Any, min_hits: int = 3) -> int:
    """Promotes high-hit IOC patterns into the evolved pattern DB.

    IOCs that have been matched min_hits+ times are reliable enough
    to become permanent regex patterns.

    Args:
        ioc_store: The Sentinel IOCStore instance.
        min_hits: Minimum hit count to qualify for promotion.

    Returns:
        Number of new patterns promoted.
    """
    data = _load_evolved_patterns()
    existing_hashes = {
        p.get("hash") for p in data["patterns"]
    }

    promoted = 0
    for ioc in ioc_store.get_all():
        if ioc.hit_count < min_hits:
            continue
        if not _validate_regex(ioc.pattern):
            continue
        h = _compute_pattern_hash(ioc.pattern)
        if h in existing_hashes:
            continue

        new_pat = {
            "id": f"IOC-PROMOTED-{ioc.ioc_id[:6].upper()}",
            "name": f"Promoted IOC • {ioc.category.value}",
            "pattern": ioc.pattern,
            "severity": ioc.severity,
            "category": ioc.category.value,
            "source": f"sentinel_node:{ioc.source_node}",
            "auto_generated": True,
            "hash": h,
            "promoted_from_ioc": ioc.ioc_id,
            "hits_at_promotion": ioc.hit_count,
        }
        data["patterns"].append(new_pat)
        existing_hashes.add(h)
        promoted += 1

    if promoted:
        _save_evolved_patterns(data)
        logger.info("Promoted %d IOC patterns to evolved DB.", promoted)

    return promoted


# ---------------------------------------------------------------------------
# Main updater class
# ---------------------------------------------------------------------------


class PatternUpdater:
    """Orchestrates automatic pattern updates and evolution.

    Runs a background loop that:
        1. Fetches raw prompts from public threat-intel feeds.
        2. Uses the Guardian LLM to synthesise generalised regex patterns.
        3. Promotes high-hit IOC patterns from the Sentinel store.
        4. Deduplicates and persists all new patterns.
        5. Hot-reloads them into the injection agent without restart.

    Example:
        >>> updater = PatternUpdater(ioc_store=sentinel.get_ioc_store())
        >>> await updater.start()
        >>> # Runs every UPDATE_INTERVAL_HOURS == 6 hours
        >>> summary = await updater.run_now()
    """

    UPDATE_INTERVAL_HOURS: float = 6.0

    def __init__(self, ioc_store: Any | None = None) -> None:
        """Initialises the pattern updater.

        Args:
            ioc_store: Optional IOCStore for IOC promotion.
        """
        self._ioc_store = ioc_store
        self._task: asyncio.Task[None] | None = None
        self._running: bool = False
        self._last_run: datetime | None = None
        self._total_added: int = 0

    async def start(self) -> None:
        """Starts the background update loop."""
        if self._running:
            return
        self._running = True
        
        # Fresh startup: Load already evolved patterns from disk into the agent memory
        existing = _load_evolved_patterns().get("patterns", [])
        if existing:
            self._hot_reload(existing)
            logger.info("Loaded %d evolved patterns from disk at startup.", len(existing))

        self._task = asyncio.create_task(
            self._loop(), name="pattern-updater"
        )
        logger.info(
            "PatternUpdater started: interval=%.0fh", self.UPDATE_INTERVAL_HOURS
        )

    async def stop(self) -> None:
        """Stops the background update loop."""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("PatternUpdater stopped.")

    async def run_now(self) -> dict[str, Any]:
        """Triggers an immediate pattern update cycle.

        Returns:
            Summary dict with added counts per source.
        """
        logger.info("PatternUpdater: starting manual update cycle.")
        return await self._update_cycle()

    async def get_status(self) -> dict[str, Any]:
        """Returns updater status for the dashboard.

        Returns:
            Dict with last_run, total_added, pattern_count.
        """
        evolved = _load_evolved_patterns()
        return {
            "running": self._running,
            "last_run": (
                self._last_run.isoformat() if self._last_run else None
            ),
            "total_patterns_added": self._total_added,
            "evolved_pattern_count": len(evolved.get("patterns", [])),
            "feeds_configured": len(_PUBLIC_FEEDS),
        }

    async def _loop(self) -> None:
        """Background periodic update loop."""
        # Run once on startup (after 30s delay)
        await asyncio.sleep(30.0)
        while self._running:
            try:
                result = await self._update_cycle()
                self._total_added += result.get("total_new", 0)
                self._last_run = datetime.now(timezone.utc)
            except Exception as exc:  # pylint: disable=broad-except
                logger.error("PatternUpdater cycle error: %s", exc)
            await asyncio.sleep(self.UPDATE_INTERVAL_HOURS * 3600)

    async def _update_cycle(self) -> dict[str, Any]:
        """Runs one full update cycle: fetch → synthesise → promote.

        Returns:
            Summary dict with per-source counts.
        """
        summary: dict[str, Any] = {"sources": {}, "total_new": 0}
        data = _load_evolved_patterns()
        existing_hashes = {p.get("hash") for p in data["patterns"]}
        newly_added: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=20.0) as client:
            tasks = [_fetch_feed(feed, client) for feed in _PUBLIC_FEEDS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for feed, raw_prompts in zip(_PUBLIC_FEEDS, results):
            if isinstance(raw_prompts, Exception) or not raw_prompts:
                summary["sources"][feed["name"]] = 0
                continue

            synthesised = await synthesise_patterns_from_prompts(
                raw_prompts, feed["name"]
            )
            new_for_feed = 0
            for pat in synthesised:
                h = pat.get("hash", _compute_pattern_hash(pat["pattern"]))
                if h not in existing_hashes:
                    newly_added.append(pat)
                    existing_hashes.add(h)
                    new_for_feed += 1

            summary["sources"][feed["name"]] = new_for_feed

        # Promote IOC patterns
        ioc_promoted = 0
        if self._ioc_store:
            ioc_promoted = promote_ioc_patterns(self._ioc_store)
            summary["ioc_promoted"] = ioc_promoted

        if newly_added:
            data["patterns"].extend(newly_added)
            _save_evolved_patterns(data)
            self._hot_reload(newly_added)

        summary["total_new"] = len(newly_added) + ioc_promoted
        logger.info(
            "PatternUpdater cycle complete: %d new patterns, %d IOC promoted.",
            len(newly_added),
            ioc_promoted,
        )
        return summary

    @staticmethod
    def _hot_reload(new_patterns: list[dict[str, Any]]) -> None:
        """Hot-reloads new patterns into the injection agent at runtime.

        Args:
            new_patterns: List of new pattern dicts to inject.
        """
        try:
            from llm_wall.guardian.agents import (  # pylint: disable=import-outside-toplevel
                injection_agent,
            )
            for pat in new_patterns:
                raw_pattern = pat.get("pattern", "")
                if not raw_pattern or not _validate_regex(raw_pattern):
                    continue
                compiled = re.compile(
                    raw_pattern, re.IGNORECASE | re.DOTALL
                )
                entry = (pat, compiled)
                cat = pat.get("category", "jailbreak")
                if cat in ("prompt_injection", "tool_abuse", "data_exfiltration"):
                    injection_agent._COMPILED_INJECTION.append(entry)  # pylint: disable=protected-access
                else:
                    injection_agent._COMPILED_JAILBREAK.append(entry)  # pylint: disable=protected-access

            logger.info(
                "Hot-reload: injected %d new patterns into agent (no restart).",
                len(new_patterns),
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.warning("Pattern hot-reload failed: %s", exc)


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_updater_instance: PatternUpdater | None = None


def get_pattern_updater(
    ioc_store: Any | None = None,
) -> PatternUpdater:
    """Returns the singleton PatternUpdater instance.

    Args:
        ioc_store: IOCStore for IOC promotion (only used on first call).

    Returns:
        Global PatternUpdater singleton.
    """
    global _updater_instance  # pylint: disable=global-statement
    if _updater_instance is None:
        _updater_instance = PatternUpdater(ioc_store=ioc_store)
    return _updater_instance
