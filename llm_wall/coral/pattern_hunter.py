from __future__ import annotations

import hashlib
import json
import logging
import re
from pathlib import Path
from typing import Any

from llm_wall.config import get_settings
from llm_wall.coral.engine import get_coral_engine
from llm_wall.guardian.llm_clients import call_analysis_llm

logger = logging.getLogger(__name__)

_SYNTHESIS_SCHEMA = """
Respond with exactly this JSON schema — an array of objects:
[
  {
    "id": "ORG-<3 digit number>",
    "name": "<short descriptive name>",
    "pattern": "<Python regex pattern, case-insensitive>",
    "severity": <integer 1-10>,
    "category": "<prompt_injection|jailbreak|goal_hijacking|data_exfiltration|tool_abuse|llmjacking>",
    "rationale": "<why this pattern is dangerous for this org>"
  }
]
Generate at most 5 patterns. Patterns must be valid Python regex.
"""

_ORG_PATTERNS_FILE = Path(get_settings().data_dir / "org_patterns.json")


def _compute_hash(text: str) -> str:
    return hashlib.md5(text.lower().strip().encode()).hexdigest()[:8]


def _validate_regex(pattern: str) -> bool:
    try:
        re.compile(pattern, re.IGNORECASE | re.DOTALL)
        return True
    except re.error:
        return False


def _load_org_patterns() -> dict[str, Any]:
    if not _ORG_PATTERNS_FILE.exists():
        return {"metadata": {"last_updated": None, "total_patterns": 0}, "patterns": []}
    with _ORG_PATTERNS_FILE.open("r", encoding="utf-8") as fp:
        return json.load(fp)


def _save_org_patterns(data: dict[str, Any]) -> None:
    from datetime import datetime, timezone
    _ORG_PATTERNS_FILE.parent.mkdir(parents=True, exist_ok=True)
    data["metadata"]["last_updated"] = datetime.now(timezone.utc).isoformat()
    data["metadata"]["total_patterns"] = len(data["patterns"])
    with _ORG_PATTERNS_FILE.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2)


def get_org_patterns() -> list[dict[str, Any]]:
    return _load_org_patterns().get("patterns", [])


class PatternHunter:
    """Coral-powered pattern evolution from org-specific data.

    Queries the organization's own GitHub repos, Notion docs, and
    Slack channels to find exposed prompts, system instructions,
    API keys, and internal terminology — then synthesises targeted
    regex patterns for the Guardian.
    """

    def __init__(self) -> None:
        self._total_discovered: int = 0
        self._last_run: str | None = None

    async def hunt(self) -> dict[str, Any]:
        """Runs one hunt cycle across all available Coral sources.

        Returns:
            Summary dict with discovered patterns per source.
        """
        from datetime import datetime, timezone
        coral = get_coral_engine()
        summary: dict[str, Any] = {"sources": {}, "total_new": 0}
        data = _load_org_patterns()
        existing_hashes = {p.get("hash") for p in data["patterns"]}

        queries: list[tuple[str, str]] = [
            ("github_readme", """
                SELECT full_name, description, readme
                FROM github.repos
                WHERE visibility = 'internal' OR visibility = 'private'
                LIMIT 20
            """),
            ("github_issues_comments", """
                SELECT body
                FROM github.issue_comments
                WHERE LENGTH(body) > 50
                ORDER BY updated_at DESC
                LIMIT 30
            """),
            ("notion_pages", """
                SELECT id, title, plain_text
                FROM notion.pages
                WHERE plain_text IS NOT NULL
                LIMIT 20
            """),
        ("slack_messages_security", """
            SELECT text, channel_name
            FROM slack.messages
            WHERE channel_name IN ('security', 'engineering', 'llm')
              AND LENGTH(text) > 50
            ORDER BY timestamp DESC
            LIMIT 30
        """),
        ]

        for source_name, sql in queries:
            try:
                rows = await coral.sql(sql)
                if not rows:
                    summary["sources"][source_name] = 0
                    continue
                patterns = await self._synthesise_from_rows(rows, source_name, existing_hashes)
                new_count = 0
                for pat in patterns:
                    h = pat.get("hash", _compute_hash(pat["pattern"]))
                    if h not in existing_hashes:
                        data["patterns"].append(pat)
                        existing_hashes.add(h)
                        new_count += 1
                summary["sources"][source_name] = new_count
            except Exception as exc:
                logger.debug("Pattern hunt failed for %s: %s", source_name, exc)
                summary["sources"][source_name] = 0

        if summary["total_new"] > 0:
            _save_org_patterns(data)
            self._total_discovered += summary["total_new"]
            self._hot_reload(data["patterns"])

        self._last_run = datetime.now(timezone.utc).isoformat()
        logger.info("PatternHunter: %d new org-specific patterns", summary["total_new"])
        return summary

    async def _synthesise_from_rows(
        self,
        rows: list[dict[str, Any]],
        source_name: str,
        existing_hashes: set[str],
    ) -> list[dict[str, Any]]:
        """Sends discovered org data to LLM for pattern synthesis."""
        combined = json.dumps(rows[:5], indent=2)[:3000]
        prompt = (
            f"You are a security regex engineer. Below is data from the "
            f"organization's '{source_name}' source. It contains internal "
            f"project names, API endpoints, prompt templates, system instructions, "
            f"and potentially sensitive patterns. Synthesise Python regex patterns "
            f"that the Guardian security engine should watch for — things like:\n"
            f"- System prompt templates that could be targeted for extraction\n"
            f"- Internal tool names that attackers might use for context\n"
            f"- API key patterns or token formats used internally\n"
            f"- Confidential terms that shouldn't appear in LLM prompts\n\n"
            f"Org data sample:\n{combined}"
        )
        try:
            result = await call_analysis_llm(prompt, _SYNTHESIS_SCHEMA)
            raw_list = result if isinstance(result, list) else result.get("patterns", [])
            validated: list[dict[str, Any]] = []
            for item in raw_list:
                pat = item.get("pattern", "")
                if not pat or not _validate_regex(pat):
                    continue
                item["source"] = f"coral:{source_name}"
                item["auto_generated"] = True
                item["hash"] = _compute_hash(pat)
                validated.append(item)
            return validated
        except Exception as exc:
            logger.warning("Pattern synthesis failed for %s: %s", source_name, exc)
            return []

    @staticmethod
    def _hot_reload(patterns: list[dict[str, Any]]) -> None:
        """Injects org patterns into the injection agent at runtime."""
        try:
            from llm_wall.guardian.agents import injection_agent
            for pat in patterns:
                raw = pat.get("pattern", "")
                if not raw or not _validate_regex(raw):
                    continue
                compiled = re.compile(raw, re.IGNORECASE | re.DOTALL)
                entry = (pat, compiled)
                cat = pat.get("category", "jailbreak")
                if cat in ("prompt_injection", "data_exfiltration", "tool_abuse"):
                    injection_agent._COMPILED_INJECTION.append(entry)
                else:
                    injection_agent._COMPILED_JAILBREAK.append(entry)
            logger.info(
                "Hot-reloaded %d org-specific patterns into injection agent.",
                len(patterns),
            )
        except Exception as exc:
            logger.warning("Pattern hot-reload failed: %s", exc)

    def stats(self) -> dict[str, Any]:
        return {
            "total_discovered": self._total_discovered,
            "last_run": self._last_run,
            "pattern_count": len(get_org_patterns()),
        }


_hunter_instance: PatternHunter | None = None


def get_pattern_hunter() -> PatternHunter:
    global _hunter_instance
    if _hunter_instance is None:
        _hunter_instance = PatternHunter()
    return _hunter_instance
