# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
"""Centralised, environment-driven configuration for LLM Wall.

All settings are read from environment variables (or a .env file).
Pydantic-Settings validates types and provides defaults so the
application can start in a useful default state.

Google Python Style Guide: settings use UPPER_SNAKE_CASE for env vars
and are exposed as lower_snake_case attributes on the Settings object.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Literal

from pydantic import Field, HttpUrl, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)


class LLMProviderSettings(BaseSettings):
    """Settings for a single LLM provider."""

    model_config = SettingsConfigDict(extra="ignore")

    # --- OpenAI ---
    openai_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="OpenAI API key.",
    )
    openai_base_url: str = Field(
        default="https://api.openai.com/v1",
        description="OpenAI-compatible base URL.",
    )
    openai_default_model: str = Field(
        default="gpt-4o-mini",
        description="Default OpenAI model.",
    )

    # --- Google Gemini ---
    gemini_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="Google Gemini API key.",
    )
    gemini_default_model: str = Field(
        default="gemini-1.5-flash",
        description="Default Gemini model.",
    )

    # --- Ollama ---
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama server base URL.",
    )
    ollama_default_model: str = Field(
        default="llama3.2:3b",
        description="Default Ollama model for guardian analysis.",
    )

    # --- NVIDIA NIM (Kimi 2.5) ---
    nvidia_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="NVIDIA NIM API key.",
    )
    nvidia_base_url: str = Field(
        default="https://integrate.api.nvidia.com/v1",
        description="NVIDIA NIM base URL.",
    )
    nvidia_default_model: str = Field(
        default="mistralai/mistral-small-3.1-24b-instruct",
        description="Default NVIDIA NIM model.",
    )


class GuardianSettings(BaseSettings):
    """Settings for the Guardian analysis engine."""

    model_config = SettingsConfigDict(extra="ignore")

    guardian_analysis_provider: Literal[
        "ollama", "openai", "gemini", "nvidia"
    ] = Field(
        default="ollama",
        description="LLM provider used for Guardian analysis.",
    )
    guardian_risk_threshold_block: int = Field(
        default=75,
        ge=0,
        le=100,
        description="Risk score ≥ threshold → block request.",
    )
    guardian_risk_threshold_quarantine: int = Field(
        default=50,
        ge=0,
        le=100,
        description="Risk score ≥ threshold → quarantine for A2A review.",
    )
    guardian_parallel_agents: bool = Field(
        default=False,
        description="Run Guardian agents in parallel.",
    )
    guardian_timeout_secs: float = Field(
        default=30.0,
        description="Per-agent analysis timeout in seconds.",
    )


class SentinelSettings(BaseSettings):
    """Settings for the Sentinel mesh node."""

    model_config = SettingsConfigDict(extra="ignore")

    sentinel_node_id: str = Field(
        default="",
        description="Unique node ID; auto-generated if empty.",
    )
    sentinel_peers: str = Field(
        default="",
        description="Comma-separated list of peer URLs for gossip.",
    )
    sentinel_gossip_interval_secs: float = Field(
        default=30.0,
        description="How often to gossip threat intel to peers.",
    )
    sentinel_max_ioc_age_hours: int = Field(
        default=72,
        description="Evict IOCs older than this many hours.",
    )

    @property
    def peer_list(self) -> list[str]:
        """Returns parsed list of peer URLs.

        Returns:
            List of non-empty peer URL strings.
        """
        if not self.sentinel_peers:
            return []
        return [p.strip() for p in self.sentinel_peers.split(",") if p.strip()]


class LedgerSettings(BaseSettings):
    """Settings for the blockchain audit ledger."""

    model_config = SettingsConfigDict(extra="ignore")

    ledger_difficulty: int = Field(
        default=2,
        ge=1,
        le=5,
        description="Proof-of-work difficulty (leading zeros).",
    )
    ledger_persist_path: str = Field(
        default="./data/ledger.json",
        description="Path to persist the blockchain JSON.",
    )


class MARLSettings(BaseSettings):
    """Settings for the MARL defense engine."""

    model_config = SettingsConfigDict(extra="ignore")

    marl_learning_rate: float = Field(
        default=0.1,
        description="Q-learning alpha.",
    )
    marl_discount_factor: float = Field(
        default=0.9,
        description="Q-learning gamma.",
    )
    marl_epsilon: float = Field(
        default=0.2,
        description="Exploration rate (epsilon-greedy).",
    )
    marl_epsilon_decay: float = Field(
        default=0.995,
        description="Epsilon decay per episode.",
    )
    marl_epsilon_min: float = Field(
        default=0.01,
        description="Minimum exploration rate.",
    )
    marl_persist_path: str = Field(
        default="./data/q_table.json",
        description="Path to persist the Q-table.",
    )


class Settings(
    LLMProviderSettings,
    GuardianSettings,
    SentinelSettings,
    LedgerSettings,
    MARLSettings,
):
    """Aggregate application settings loaded from environment / .env.

    Example:
        >>> from llm_wall.config import get_settings
        >>> cfg = get_settings()
        >>> print(cfg.ollama_base_url)
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="LLM Wall", description="Application name.")
    app_system_purpose: str = Field(
        default=(
            "This system is a professional LLM interface for business "
            "operations. It should not be used for personal, creative, "
            "or unrelated entertainment purposes."
        ),
        description="The prescribed purpose/mission of this AI system.",
    )
    app_env: Literal["development", "staging", "production"] = Field(
        default="development",
        description="Deployment environment.",
    )
    app_host: str = Field(default="0.0.0.0", description="Bind host.")
    app_port: int = Field(default=8000, description="Bind port.")
    app_workers: int = Field(default=1, description="Uvicorn worker count.")
    app_log_level: Literal["debug", "info", "warning", "error"] = Field(
        default="info",
        description="Log level.",
    )
    secret_key: SecretStr = Field(
        default=SecretStr("change-me-in-production-32-chars!!"),
        description="Secret key for JWT signing.",
    )
    cors_origins: str = Field(
        default="http://localhost:3000,http://localhost:5173",
        description="Comma-separated allowed CORS origins.",
    )
    data_dir: Path = Field(
        default=Path("./data"),
        description="Directory for persistent data (ledger, Q-tables, etc.).",
    )

    @property
    def allowed_origins(self) -> list[str]:
        """Returns parsed list of CORS origins.

        Returns:
            List of origin strings.
        """
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @field_validator("app_env", mode="before")
    @classmethod
    def normalise_env(cls, value: str) -> str:
        """Normalises the APP_ENV string to lowercase.

        Args:
            value: Raw environment string.

        Returns:
            Lowercased environment string.
        """
        return str(value).lower()


_settings: Settings | None = None


def get_settings() -> Settings:
    """Returns the singleton Settings instance.

    Uses module-level caching to avoid re-parsing env vars on every call.

    Returns:
        The global Settings singleton.
    """
    global _settings  # pylint: disable=global-statement
    if _settings is None:
        _settings = Settings()
        logger.info(
            "Settings loaded: env=%s provider=%s",
            _settings.app_env,
            _settings.guardian_analysis_provider,
        )
    return _settings
