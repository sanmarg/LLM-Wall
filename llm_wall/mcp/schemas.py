# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""MCP broker internal schemas."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import BaseModel

from llm_wall.mcp.tool_policies import ToolPolicy


@dataclass
class RegistryEntry:
    """Internal registry entry for a registered MCP tool.

    Attributes:
        name: Tool identifier.
        implementation: Callable that performs the tool's work.
        policy: Security policy applied to this tool.
        description: Human-readable tool description.
        allowed_roles: Permitted caller roles.
    """

    name: str
    implementation: Callable[..., Any]
    policy: ToolPolicy
    description: str = ""
    allowed_roles: list[str] = field(default_factory=list)


class MCPServerInfo(BaseModel):
    """MCP server discovery response."""

    tool_count: int
    invocation_count: int
    block_count: int
    tools: list[dict[str, Any]] = []
