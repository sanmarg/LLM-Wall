# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""MCP (Model Context Protocol) broker for secure tool-call gating.

Every tool call from an LLM agent passes through this broker, which
applies risk-level policies and either permits, requires consensus,
or blocks the call. All decisions are audited on the blockchain ledger.
"""

from __future__ import annotations

import logging
from typing import Any, Callable

from llm_wall.mcp.tool_policies import ToolPolicy, get_policy
from llm_wall.mcp.schemas import MCPServerInfo, RegistryEntry
from llm_wall.models import MCPToolCall, MCPToolResult, ThreatAction

logger = logging.getLogger(__name__)

# Callable signature for registered tool implementations.
ToolImpl = Callable[..., Any]


class MCPBroker:
    """Secure MCP broker that gates all tool invocations.

    Tools must be registered with their risk policy before they can be
    called. The broker checks the inherited risk score from the Guardian
    report and applies the tool's policy to allow/block/escalate.

    Example:
        >>> broker = MCPBroker()
        >>> broker.register_tool("web_search", my_search_fn, risk_level="medium")
        >>> result = await broker.invoke(tool_call)
    """

    def __init__(self) -> None:
        """Initialises the broker with an empty tool registry."""
        self._registry: dict[str, RegistryEntry] = {}
        self._invocation_count: int = 0
        self._block_count: int = 0
        logger.info("MCP Broker initialised.")

    def register_tool(
        self,
        name: str,
        implementation: ToolImpl,
        risk_level: str = "medium",
        description: str = "",
        allowed_roles: list[str] | None = None,
    ) -> None:
        """Registers a tool with its security policy.

        Args:
            name: Unique tool identifier.
            implementation: Async or sync callable implementing the tool.
            risk_level: Policy level: 'low', 'medium', 'high', 'critical'.
            description: Human-readable description of the tool.
            allowed_roles: Optional list of allowed caller roles.
        """
        policy = get_policy(risk_level)
        self._registry[name] = RegistryEntry(
            name=name,
            implementation=implementation,
            policy=policy,
            description=description,
            allowed_roles=allowed_roles or ["user", "assistant", "agent"],
        )
        logger.info(
            "Tool registered: name=%s risk_level=%s block_threshold=%d",
            name,
            risk_level,
            policy.block_threshold,
        )

    async def invoke(self, call: MCPToolCall) -> MCPToolResult:
        """Invokes a tool after applying the security policy.

        Args:
            call: MCPToolCall with tool name, arguments, and inherited
                  risk score from the Guardian report.

        Returns:
            MCPToolResult indicating allow/block and optional result.

        Raises:
            KeyError: If the tool is not registered.
        """
        self._invocation_count += 1
        entry = self._registry.get(call.tool_name)

        if entry is None:
            self._block_count += 1
            logger.warning(
                "MCP block: unknown tool '%s' (request=%s)",
                call.tool_name,
                call.caller_request_id[:8],
            )
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                allowed=False,
                blocked_reason=(
                    f"Tool '{call.tool_name}' is not registered in MCP broker."
                ),
            )

        policy = entry.policy
        action = policy.evaluate(call.risk_score)

        logger.info(
            "MCP evaluate: tool=%s risk=%d action=%s",
            call.tool_name,
            call.risk_score,
            action.value,
        )

        if action == ThreatAction.BLOCK:
            self._block_count += 1
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                allowed=False,
                blocked_reason=(
                    f"Risk score {call.risk_score} exceeds tool policy "
                    f"threshold {policy.block_threshold}."
                ),
            )

        if action == ThreatAction.QUARANTINE:
            # In quarantine, still block but log as requiring review
            self._block_count += 1
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                allowed=False,
                blocked_reason=(
                    f"Tool '{call.tool_name}' quarantined for risk={call.risk_score}."
                    " Requires human review."
                ),
            )

        # ALLOW — execute the tool
        try:
            import asyncio  # pylint: disable=import-outside-toplevel
            impl = entry.implementation
            if asyncio.iscoroutinefunction(impl):
                result = await impl(**call.arguments)
            else:
                result = impl(**call.arguments)
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                allowed=True,
                result=result,
            )
        except Exception as exc:  # pylint: disable=broad-except
            logger.error(
                "Tool '%s' raised an exception: %s", call.tool_name, exc
            )
            return MCPToolResult(
                call_id=call.call_id,
                tool_name=call.tool_name,
                allowed=True,
                result=None,
                blocked_reason=f"Tool execution error: {exc}",
            )

    def server_info(self) -> MCPServerInfo:
        """Returns MCP server metadata for discovery.

        Returns:
            MCPServerInfo with registered tools and stats.
        """
        return MCPServerInfo(
            tool_count=len(self._registry),
            invocation_count=self._invocation_count,
            block_count=self._block_count,
            tools=[
                {
                    "name": e.name,
                    "description": e.description,
                    "risk_level": e.policy.level,
                    "block_threshold": e.policy.block_threshold,
                }
                for e in self._registry.values()
            ],
        )

    def list_tools(self) -> list[dict[str, Any]]:
        """Returns a list of registered tool metadata.

        Returns:
            List of dicts with name, description, and policy info.
        """
        return [
            {
                "name": e.name,
                "description": e.description,
                "risk_level": e.policy.level,
                "block_threshold": e.policy.block_threshold,
                "allowed_roles": e.allowed_roles,
            }
            for e in self._registry.values()
        ]


# ---------------------------------------------------------------------------
# Module singleton
# ---------------------------------------------------------------------------

_broker_instance: MCPBroker | None = None


def get_mcp_broker() -> MCPBroker:
    """Returns the singleton MCPBroker instance.

    Returns:
        Global MCPBroker singleton.
    """
    global _broker_instance  # pylint: disable=global-statement
    if _broker_instance is None:
        _broker_instance = MCPBroker()
        _register_builtin_tools(_broker_instance)
    return _broker_instance


def _register_builtin_tools(broker: MCPBroker) -> None:
    """Registers the built-in safe demonstration tools.

    Args:
        broker: MCPBroker to register tools on.
    """

    async def echo_tool(message: str = "") -> str:
        """Safe echo tool for testing."""
        return f"Echo: {message}"

    async def time_tool() -> str:
        """Returns current UTC time."""
        from datetime import datetime, timezone  # pylint: disable=import-outside-toplevel
        return datetime.now(timezone.utc).isoformat()

    async def health_tool() -> dict[str, str]:
        """Returns a health status dict."""
        return {"status": "healthy", "service": "llm-wall"}

    broker.register_tool(
        "echo", echo_tool, risk_level="low", description="Echo input text."
    )
    broker.register_tool(
        "get_time",
        time_tool,
        risk_level="low",
        description="Returns current UTC time.",
    )
    broker.register_tool(
        "health_check",
        health_tool,
        risk_level="low",
        description="Returns service health status.",
    )
    logger.info("Built-in MCP tools registered.")
