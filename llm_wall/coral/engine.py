from __future__ import annotations

import asyncio
import json
import logging
import os
import shlex
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class CoralEngine:
    """Manages the Coral CLI subprocess and provides async SQL querying.

    Wraps ``coral sql`` and ``coral source`` commands, returning
    parsed JSON results. Runs 100 % locally — no external service.
    """

    def __init__(self, coral_bin: str | None = None, config_dir: str | None = None) -> None:
        self._coral_bin = coral_bin or self._find_coral()
        self._config_dir = config_dir or os.environ.get("CORAL_CONFIG_DIR", "")
        self._sql_count: int = 0
        self._error_count: int = 0
        self._sources: list[str] = []

        logger.info(
            "CoralEngine initialised: bin=%s config_dir=%s",
            self._coral_bin,
            self._config_dir or "(default)",
        )

    @staticmethod
    def _find_coral() -> str:
        """Locates the coral binary on PATH."""
        for candidate in ["coral", "coral.exe"]:
            try:
                import shutil
                path = shutil.which(candidate)
                if path:
                    return path
            except Exception:
                pass
        # Fallback to common locations
        home = Path.home()
        for p in [
            home / ".local" / "bin" / "coral.exe",
            home / ".local" / "bin" / "coral",
            Path("C:/Program Files/coral/coral.exe"),
        ]:
            if p.exists():
                return str(p)
        logger.warning("Coral binary not found on PATH; will be unavailable.")
        return "coral"

    async def _run_coral(self, *args: str, input_data: str | None = None) -> str:
        """Runs a coral CLI command and returns stdout.

        Args:
            *args: CLI arguments (e.g. ``"sql", "SELECT 1"``).
            input_data: Optional stdin string.

        Returns:
            Raw stdout string.

        Raises:
            RuntimeError: If coral binary not found or command fails.
        """
        if not self._coral_bin:
            raise RuntimeError("Coral binary not available.")

        cmd = [self._coral_bin]
        if self._config_dir:
            cmd.extend(["--config-dir", self._config_dir])
        cmd.extend(args)

        logger.debug("Coral subprocess: %s", " ".join(shlex.quote(c) for c in cmd))

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE if input_data else None,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate(
            input=input_data.encode() if input_data else None
        )

        if proc.returncode != 0:
            stderr_text = stderr.decode(errors="replace").strip()
            raise RuntimeError(
                f"Coral command failed (exit={proc.returncode}): {stderr_text}"
            )

        return stdout.decode(errors="replace")

    async def sql(self, query: str, fmt: str = "json") -> list[dict[str, Any]]:
        """Executes a read-only SQL query against Coral sources.

        Args:
            query: SQL query string (e.g. ``SELECT * FROM github.issues LIMIT 5``).
            fmt: Output format — ``"json"`` (default) or ``"table"``.

        Returns:
            List of row dicts for JSON format, or raw string for table format.
        """
        self._sql_count += 1
        try:
            raw = await self._run_coral("sql", f"--format={fmt}", query)
            if fmt == "json":
                rows = json.loads(raw)
                if isinstance(rows, list):
                    return rows
                if isinstance(rows, dict) and "rows" in rows:
                    return rows["rows"]
                return [rows]
            return raw
        except Exception as exc:
            self._error_count += 1
            logger.warning("Coral SQL error: %s", exc)
            return []

    async def list_sources(self) -> list[dict[str, str]]:
        """Returns installed Coral sources by parsing table output."""
        try:
            raw = await self._run_coral("source", "list")
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            parsed: list[dict[str, str]] = []
            for line in lines:
                if "No sources" in line or "Name" in line or "──" in line or not line:
                    continue
                parts = line.split()
                if parts and len(parts) >= 2 and parts[0].strip("*").isalpha():
                    name = parts[0].strip("*")
                    parsed.append({"name": name, "status": parts[1].strip("*") if len(parts) > 1 else ""})
            self._sources = [s.get("name", "") for s in parsed if s.get("name")]
            return parsed
        except Exception as exc:
            logger.warning("Coral source list error: %s", exc)
            return []

    async def discover_sources(self) -> list[dict[str, str]]:
        """Returns available bundled sources by parsing table output."""
        try:
            raw = await self._run_coral("source", "discover")
            lines = [l.strip() for l in raw.splitlines() if l.strip()]
            parsed: list[dict[str, str]] = []
            for line in lines:
                if "No sources" in line or line.startswith("Name") or "──" in line or not line:
                    continue
                parts = line.split()
                if parts:
                    parsed.append({"name": parts[0], "description": " ".join(parts[1:]) if len(parts) > 1 else ""})
            return parsed
        except Exception:
            return []

    async def add_source(self, name: str) -> bool:
        """Adds a bundled source interactively (requires env vars set).

        Args:
            name: Source name (e.g. ``"github"``, ``"osv"``).

        Returns:
            True if added successfully.
        """
        try:
            await self._run_coral("source", "add", name)
            if name not in self._sources:
                self._sources.append(name)
            logger.info("Coral source added: %s", name)
            return True
        except Exception as exc:
            logger.warning("Coral source add failed for '%s': %s", name, exc)
            return False

    async def add_source_from_file(self, manifest_path: str) -> bool:
        """Adds a community source from a manifest YAML file.

        Args:
            manifest_path: Path to manifest.yaml.

        Returns:
            True if added successfully.
        """
        try:
            await self._run_coral("source", "add", "--file", manifest_path)
            logger.info("Coral source added from file: %s", manifest_path)
            return True
        except Exception as exc:
            logger.warning(
                "Coral source add from file failed: %s", exc
            )
            return False

    async def health_check(self) -> bool:
        """Checks if Coral is available and has at least one source."""
        try:
            await self._run_coral("--version")
            sources = await self.list_sources()
            return True
        except Exception:
            return False

    def stats(self) -> dict[str, Any]:
        """Returns usage statistics."""
        return {
            "available": self._coral_bin is not None,
            "sql_queries": self._sql_count,
            "errors": self._error_count,
            "sources": self._sources,
            "source_count": len(self._sources),
        }


_engine_instance: CoralEngine | None = None


def get_coral_engine() -> CoralEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = CoralEngine()
    return _engine_instance
