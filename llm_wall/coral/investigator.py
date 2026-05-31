from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any

from llm_wall.a2a.bus import (
    TOPIC_IOC_NEW,
    TOPIC_THREAT_BLOCKED,
    TOPIC_THREAT_DETECTED,
    get_bus,
)
from llm_wall.coral.engine import get_coral_engine
from llm_wall.ledger.node import get_ledger_node
from llm_wall.models import (
    A2AMessage,
    CoralInvestigationReport,
    CoralSnapshot,
    ThreatAction,
)

logger = logging.getLogger(__name__)

_DEFAULT_SQL = {
    "recent_github_activity": """
        SELECT id, title, state, merged_at, user_login
        FROM github.pull_requests
        WHERE merged_at >= datetime('now', '-24 hours')
        ORDER BY merged_at DESC
        LIMIT 10
    """,
    "sentry_errors": """
        SELECT id, title, level, count, first_seen, last_seen
        FROM sentry.issues
        WHERE level IN ('fatal', 'error')
          AND first_seen >= datetime('now', '-6 hours')
        ORDER BY first_seen DESC
        LIMIT 10
    """,
    "slack_incidents": """
        SELECT ts, user, text, channel_name
        FROM slack.messages
        WHERE channel_name IN ('incidents', 'security', 'engineering')
          AND timestamp >= datetime('now', '-6 hours')
        ORDER BY timestamp DESC
        LIMIT 20
    """,
    "pagerduty_incidents": """
        SELECT id, title, urgency, status, created_at
        FROM pagerduty.incidents
        WHERE status = 'triggered'
           OR created_at >= datetime('now', '-24 hours')
        ORDER BY created_at DESC
        LIMIT 10
    """,
    "datadog_anomalies": """
        SELECT id, title, status, last_status_change, severity
        FROM datadog.incidents
        WHERE status = 'active'
           OR last_status_change >= datetime('now', '-6 hours')
        ORDER BY last_status_change DESC
        LIMIT 10
    """,
}


class IncidentInvestigator:
    """A2A subscriber that auto-investigates threats using Coral.

    Subscribes to threat.detected / threat.blocked topics,
    runs cross-source Coral SQL queries, stores results on
    the blockchain ledger, and publishes investigation.complete.
    """

    def __init__(self) -> None:
        self._running: bool = False
        self._investigation_count: int = 0
        self._reports: list[CoralInvestigationReport] = []
        self._max_reports: int = 200

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        bus = get_bus()
        bus.subscribe(TOPIC_THREAT_DETECTED, self._on_threat_detected)
        bus.subscribe(TOPIC_THREAT_BLOCKED, self._on_threat_blocked)
        logger.info("IncidentInvestigator started (subscribed to threat topics).")

    async def stop(self) -> None:
        self._running = False
        logger.info("IncidentInvestigator stopped.")

    async def _on_threat_detected(self, msg: A2AMessage) -> None:
        risk = msg.payload.get("risk_score", 0)
        if risk < 40:
            return
        await self._investigate(msg)

    async def _on_threat_blocked(self, msg: A2AMessage) -> None:
        await self._investigate(msg)

    async def _run_queries(self, timeout_per_query: float = 3.0) -> tuple[dict[str, Any], list[str]]:
        """Runs all default Coral SQL queries with a per-query timeout.

        Args:
            timeout_per_query: Max seconds per query.

        Returns:
            (results dict, errors list)
        """
        coral = get_coral_engine()
        results: dict[str, Any] = {}
        errors: list[str] = []

        async def run_one(name: str, sql: str) -> tuple[str, list | Exception]:
            try:
                rows = await asyncio.wait_for(coral.sql(sql), timeout=timeout_per_query)
                return name, rows
            except Exception as exc:
                return name, exc

        tasks = [run_one(qn, qs) for qn, qs in _DEFAULT_SQL.items()]
        done = await asyncio.gather(*tasks, return_exceptions=True)
        for item in done:
            if isinstance(item, Exception):
                continue
            name, result = item
            if isinstance(result, Exception):
                errors.append(f"{name}: {result}")
                logger.debug("Coral query '%s' failed: %s", name, result)
            elif result:
                results[name] = result

        if not results and not errors:
            results["_note"] = "No Coral sources configured — install with: coral source add <name>"
        return results, errors

    async def _investigate(self, msg: A2AMessage) -> None:
        self._investigation_count += 1
        request_id = msg.payload.get("request_id", "unknown")
        logger.info(
            "Investigation #%d for request %s",
            self._investigation_count,
            request_id[:8],
        )

        results, errors = await self._run_queries()

        report = CoralInvestigationReport(
            request_id=request_id,
            risk_score=msg.payload.get("risk_score", 0),
            decision=msg.payload.get("action", "unknown"),
            coral_results=results,
            errors=errors,
        )
        self._reports.append(report)
        if len(self._reports) > self._max_reports:
            self._reports.pop(0)

        # Store on the blockchain ledger
        try:
            ledger = get_ledger_node()
            ledger.record_investigation(report)
        except Exception as exc:
            logger.warning("Failed to record investigation on ledger: %s", exc)

        # Publish investigation.complete to A2A bus
        bus = get_bus()
        await bus.publish(
            A2AMessage(
                sender_id="incident_investigator",
                topic="investigation.complete",
                payload={
                    "request_id": request_id,
                    "investigation_id": report.investigation_id,
                    "query_count": len(results),
                    "error_count": len(errors),
                },
                priority=6,
            )
        )
        logger.info(
            "Investigation #%d complete: %d queries, %d errors",
            self._investigation_count,
            len(results),
            len(errors),
        )

    async def force_investigate(self, request_id: str, risk_score: int = 50) -> CoralInvestigationReport | None:
        """Manually triggers an investigation for dashboard / API calls."""
        results, errors = await self._run_queries()
        report = CoralInvestigationReport(
            request_id=request_id,
            risk_score=risk_score,
            decision="manual",
            coral_results=results,
            errors=errors,
        )
        self._reports.append(report)
        if len(self._reports) > self._max_reports:
            self._reports.pop(0)
        return report

    def get_recent_reports(self, limit: int = 20) -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in self._reports[-limit:]]

    def get_report(self, investigation_id: str) -> dict[str, Any] | None:
        for r in self._reports:
            if r.investigation_id == investigation_id:
                return r.model_dump(mode="json")
        return None

    def stats(self) -> dict[str, Any]:
        return {
            "investigation_count": self._investigation_count,
            "cached_reports": len(self._reports),
        }


_investigator_instance: IncidentInvestigator | None = None


def get_investigator() -> IncidentInvestigator:
    global _investigator_instance
    if _investigator_instance is None:
        _investigator_instance = IncidentInvestigator()
    return _investigator_instance
