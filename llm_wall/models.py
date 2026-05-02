# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Shared Pydantic models / schemas used across all LLM Wall subsystems.

All models follow Google Python Style Guide naming conventions:
- Classes: CapWords
- Fields: snake_case
- Constants: UPPER_SNAKE_CASE
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Provider(str, enum.Enum):
    """Supported LLM provider identifiers."""

    OPENAI = "openai"
    GEMINI = "gemini"
    OLLAMA = "ollama"
    NVIDIA = "nvidia"


class ThreatAction(str, enum.Enum):
    """Decision actions the Guardian engine can emit."""

    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    RATE_LIMIT = "rate_limit"
    ESCALATE = "escalate"


class ThreatCategory(str, enum.Enum):
    """Taxonomy of detected threat categories."""

    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    GOAL_HIJACKING = "goal_hijacking"
    IDENTITY_OVERRIDE = "identity_override"
    DATA_EXFILTRATION = "data_exfiltration"
    TOOL_ABUSE = "tool_abuse"
    LLMJACKING = "llmjacking"
    OUT_OF_SCOPE = "out_of_scope"
    BENIGN = "benign"


class RiskBand(str, enum.Enum):
    """Coarse risk classification derived from numeric score."""

    LOW = "low"        # 0-29
    MEDIUM = "medium"  # 30-69
    HIGH = "high"      # 70-100

    @classmethod
    def from_score(cls, score: int) -> "RiskBand":
        """Derives a RiskBand from a numeric 0-100 score.

        Args:
            score: Integer risk score in range [0, 100].

        Returns:
            Corresponding RiskBand enum value.
        """
        if score < 30:
            return cls.LOW
        if score < 70:
            return cls.MEDIUM
        return cls.HIGH


# ---------------------------------------------------------------------------
# LLM Request / Response Normalisation
# ---------------------------------------------------------------------------


class ChatMessage(BaseModel):
    """A single turn in a chat conversation."""

    role: str = Field(description="Message role: user, assistant, system.")
    content: str = Field(description="Message content text.")


class LLMRequest(BaseModel):
    """Normalised inbound LLM request (provider-agnostic).

    This is the internal representation created after parsing the
    raw OpenAI-compatible or provider-native request body.
    """

    request_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique request identifier.",
    )
    provider: Provider = Field(description="Target LLM provider.")
    model: str = Field(description="Model identifier.")
    messages: list[ChatMessage] = Field(
        default_factory=list,
        description="Conversation history.",
    )
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)
    max_tokens: int | None = Field(default=None)
    stream: bool = Field(default=False)
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Caller-supplied metadata (client_id, session_id, etc.).",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )

    @property
    def full_prompt(self) -> str:
        """Concatenates all message contents for analysis.

        Returns:
            Single string of all message content joined by newlines.
        """
        return "\n".join(m.content for m in self.messages)


class LLMResponse(BaseModel):
    """Normalised LLM response wrapper."""

    request_id: str = Field(description="Mirrors the originating request ID.")
    provider: Provider = Field(description="Provider that served the request.")
    model: str = Field(description="Model that generated the response.")
    content: str = Field(description="Generated text content.")
    usage: dict[str, int] = Field(
        default_factory=dict,
        description="Token usage statistics.",
    )
    latency_ms: float = Field(description="Round-trip latency in milliseconds.")


# ---------------------------------------------------------------------------
# Guardian / Threat Models
# ---------------------------------------------------------------------------


class AgentSignal(BaseModel):
    """Threat signal emitted by a single Guardian agent."""

    agent_name: str = Field(description="Name of the producing agent.")
    score: int = Field(ge=0, le=100, description="Partial risk score 0-100.")
    category: ThreatCategory = Field(description="Detected threat category.")
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        description="Agent confidence in this signal.",
    )
    evidence: list[str] = Field(
        default_factory=list,
        description="Human-readable evidence snippets.",
    )
    latency_ms: float = Field(default=0.0)


class ThreatReport(BaseModel):
    """Aggregated threat assessment produced by the Guardian engine."""

    request_id: str = Field(description="Originating request ID.")
    risk_score: int = Field(ge=0, le=100, description="Aggregated risk score.")
    risk_band: RiskBand = Field(description="Coarse risk classification.")
    action: ThreatAction = Field(description="Recommended action.")
    primary_category: ThreatCategory = Field(
        description="Dominant threat category.",
    )
    signals: list[AgentSignal] = Field(
        default_factory=list,
        description="Per-agent signals.",
    )
    explanation: str = Field(
        default="",
        description="Human-readable explanation of the decision.",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    processing_ms: float = Field(default=0.0)


# ---------------------------------------------------------------------------
# Sentinel / IOC Models
# ---------------------------------------------------------------------------


class IOC(BaseModel):
    """Indicator of Compromise shared via the Sentinel mesh."""

    ioc_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Unique IOC identifier.",
    )
    category: ThreatCategory = Field(description="Attack category.")
    pattern: str = Field(description="Pattern string or hash.")
    severity: int = Field(ge=1, le=10, description="Severity 1-10.")
    source_node: str = Field(description="Originating Sentinel node ID.")
    first_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    last_seen: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    hit_count: int = Field(default=1)
    ttl_hours: int = Field(default=72, description="Time-to-live in hours.")


# ---------------------------------------------------------------------------
# Blockchain / Ledger Models
# ---------------------------------------------------------------------------


class AuditEvent(BaseModel):
    """A single security event recorded on the audit ledger."""

    event_id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
    )
    request_id: str = Field(description="LLM request that triggered this.")
    action: ThreatAction = Field(description="Action taken.")
    risk_score: int = Field(ge=0, le=100)
    primary_category: ThreatCategory
    provider: Provider
    model: str
    actor_ip: str = Field(default="unknown")
    actor_name: str = Field(default="anonymous")
    prompt_snippet: str = Field(default="")
    signals_summary: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )


class BlockData(BaseModel):
    """Payload stored within a blockchain block."""

    events: list[AuditEvent] = Field(default_factory=list)
    iocs_added: list[str] = Field(
        default_factory=list,
        description="IOC IDs added in this block.",
    )
    node_id: str = Field(description="Ledger node that mined this block.")


# ---------------------------------------------------------------------------
# MCP Models
# ---------------------------------------------------------------------------


class MCPToolCall(BaseModel):
    """A tool invocation request intercepted by the MCP broker."""

    call_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    tool_name: str = Field(description="Name of the requested tool.")
    arguments: dict[str, Any] = Field(default_factory=dict)
    caller_request_id: str = Field(description="Originating LLM request.")
    risk_score: int = Field(ge=0, le=100, description="Inherited risk score.")


class MCPToolResult(BaseModel):
    """Result of a tool call brokered by MCP."""

    call_id: str
    tool_name: str
    allowed: bool = Field(description="Whether the call was permitted.")
    result: Any = Field(default=None)
    blocked_reason: str = Field(default="")


# ---------------------------------------------------------------------------
# A2A Models
# ---------------------------------------------------------------------------


class A2AMessage(BaseModel):
    """Message exchanged on the Agent-to-Agent bus."""

    message_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sender_id: str = Field(description="Sending agent identifier.")
    topic: str = Field(description="Pub/sub topic name.")
    payload: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    priority: int = Field(
        default=5,
        ge=1,
        le=10,
        description="Message priority (10 = highest).",
    )


class ConsensusRequest(BaseModel):
    """A2A consensus request sent when risk is in the quarantine band."""

    consensus_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    request_id: str
    risk_score: int
    signals: list[AgentSignal]
    timeout_secs: float = Field(default=3.0)


class ConsensusVote(BaseModel):
    """Vote cast by a participating agent in a consensus round."""

    consensus_id: str
    voter_id: str
    vote: ThreatAction
    confidence: float = Field(ge=0.0, le=1.0)
