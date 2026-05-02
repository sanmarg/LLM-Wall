# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""OpenAI-compatible proxy router with full Guardian/MARL/Ledger pipeline.

Every inbound request is intercepted, analysed, acted upon, and audited
before being forwarded to the real LLM provider.

Pipeline per request:
    1. Parse & normalise → LLMRequest
    2. Guardian Engine → ThreatReport
    3. MARL Engine → (overrides / learn)
    4. A2A Bus → broadcast threat signal
    5. Sentinel Node → IOC ingestion
    6. Ledger Node → AuditEvent recording
    7. If ALLOW/RATE_LIMIT → forward to provider → stream/return
    8. If BLOCK/QUARANTINE → return 403 with explanation
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from llm_wall.a2a.bus import (
    TOPIC_THREAT_BLOCKED,
    TOPIC_THREAT_DETECTED,
    get_bus,
)
from llm_wall.config import get_settings
from llm_wall.core.provider_clients import get_client
from llm_wall.guardian.engine import get_guardian_engine
from llm_wall.ledger.node import get_ledger_node
from llm_wall.marl.engine import get_marl_engine
from llm_wall.models import (
    A2AMessage,
    ChatMessage,
    LLMRequest,
    LLMResponse,
    Provider,
    ThreatAction,
)
from llm_wall.sentinel.node import get_sentinel_node

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["proxy"])


def _parse_provider(request: Request) -> Provider:
    """Extracts target provider from the X-LLM-Provider header.

    Args:
        request: The incoming FastAPI request.

    Returns:
        Provider enum value, defaulting to OLLAMA.
    """
    header = request.headers.get("X-LLM-Provider", "ollama").lower()
    try:
        return Provider(header)
    except ValueError:
        return Provider.OLLAMA


@router.post("/chat/completions")
async def chat_completions(
    request: Request,
) -> Any:
    """OpenAI-compatible chat completions endpoint with security pipeline.

    Accepts standard OpenAI chat completion request bodies. Routes to the
    configured LLM provider after passing through the Guardian + MARL
    security pipeline.

    Required header: ``X-LLM-Provider: openai|gemini|ollama|nvidia``

    Returns:
        OpenAI-compatible completion response, or 403 on block.

    Raises:
        HTTPException: 400 for invalid request body, 503 for provider errors.
    """
    cfg = get_settings()
    actor_ip = request.client.host if request.client else "unknown"

    # 1. Parse request body
    try:
        body: dict[str, Any] = await request.json()
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid JSON: {exc}") from exc

    provider = _parse_provider(request)
    model = body.get("model", "")
    messages_raw: list[dict[str, str]] = body.get("messages", [])
    messages = [
        ChatMessage(role=m.get("role", "user"), content=m.get("content", ""))
        for m in messages_raw
    ]
    # Extract identity metadata
    user_id = request.headers.get("X-User-ID", "anonymous")
    client_id = request.headers.get("X-Client-ID", "unknown-client")

    llm_request = LLMRequest(
        provider=provider,
        model=model,
        messages=messages,
        temperature=float(body.get("temperature", 0.7)),
        max_tokens=body.get("max_tokens"),
        stream=bool(body.get("stream", False)),
        metadata={
            "actor_ip": actor_ip,
            "user_id": user_id,
            "client_id": client_id,
        },
    )

    # 2. Guardian analysis
    sentinel = get_sentinel_node()
    guardian = get_guardian_engine(ioc_store=sentinel.get_ioc_store())
    t_guard = time.perf_counter()
    report = await guardian.analyse(llm_request)
    guard_ms = (time.perf_counter() - t_guard) * 1000

    logger.info(
        "Guardian: request=%s score=%d action=%s (%.1fms)",
        llm_request.request_id[:8],
        report.risk_score,
        report.action.value,
        guard_ms,
    )

    # 3. Early Exit on Hard Block
    if report.action == ThreatAction.BLOCK:
        # Finalise reports for ledger/sentinel before exit
        ledger = get_ledger_node()
        ledger.record(llm_request, report, actor_ip=actor_ip)
        sentinel.ingest_threat(report, actor_ip=actor_ip)
        
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "security_block",
                    "message": "Access Denied: High-risk threat detected by LLM Wall Guardian.",
                    "risk_score": report.risk_score,
                    "category": report.primary_category.value,
                    "explanation": report.explanation,
                    "request_id": llm_request.request_id,
                }
            },
            headers={
                "X-Risk-Score": str(report.risk_score),
                "X-Threat-Action": "block",
                "X-Request-ID": llm_request.request_id,
            },
        )

    # 4. MARL override (only for non-blocks)
    marl = get_marl_engine()
    marl_action = await marl.decide(report, provider)
    final_action = marl_action if marl_action != ThreatAction.ALLOW else report.action

    report.action = final_action

    # 4. A2A broadcast
    bus = get_bus()
    await bus.publish(
        A2AMessage(
            sender_id="proxy_router",
            topic=TOPIC_THREAT_DETECTED,
            payload={
                "request_id": llm_request.request_id,
                "risk_score": report.risk_score,
                "action": final_action.value,
                "provider": provider.value,
            },
            priority=max(1, report.risk_score // 10),
        )
    )

    # 5–6. Sentinel + Ledger (non-blocking background)
    if final_action in (ThreatAction.BLOCK, ThreatAction.QUARANTINE):
        sentinel.ingest_threat(report, actor_ip=actor_ip)
        await bus.publish(
            A2AMessage(
                sender_id="proxy_router",
                topic=TOPIC_THREAT_BLOCKED,
                payload={
                    "request_id": llm_request.request_id,
                    "risk_score": report.risk_score,
                    "category": report.primary_category.value,
                },
                priority=9,
            )
        )

    ledger = get_ledger_node()
    ledger.record(llm_request, report, actor_ip=actor_ip)

    # 7. Block / Quarantine response
    if final_action == ThreatAction.BLOCK:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "type": "security_block",
                    "message": "Request blocked by LLM Wall Guardian.",
                    "risk_score": report.risk_score,
                    "category": report.primary_category.value,
                    "explanation": report.explanation,
                    "request_id": llm_request.request_id,
                }
            },
            headers={
                "X-Risk-Score": str(report.risk_score),
                "X-Threat-Action": "block",
                "X-Request-ID": llm_request.request_id,
            },
        )

    if final_action == ThreatAction.QUARANTINE:
        return JSONResponse(
            status_code=202,
            content={
                "status": "quarantined",
                "message": "Request quarantined for review.",
                "risk_score": report.risk_score,
                "request_id": llm_request.request_id,
            },
            headers={"X-Threat-Action": "quarantine"},
        )

    # 8. Forward to provider
    client = get_client(provider)
    try:
        if llm_request.stream:
            return StreamingResponse(
                _stream_provider(client, llm_request),
                media_type="text/event-stream",
                headers={
                    "X-Risk-Score": str(report.risk_score),
                    "X-Threat-Action": final_action.value,
                },
            )
        llm_response: LLMResponse = await client.complete(llm_request)
        return JSONResponse(
            content=_to_openai_format(llm_response),
            headers={
                "X-Risk-Score": str(report.risk_score),
                "X-Threat-Action": final_action.value,
                "X-Request-ID": llm_request.request_id,
            },
        )
    except Exception as exc:
        logger.error("Provider error (%s): %s", provider.value, exc)
        raise HTTPException(
            status_code=503,
            detail=f"Provider '{provider.value}' unavailable: {exc}",
        ) from exc


async def _stream_provider(client: Any, request: LLMRequest):
    """Async generator for SSE streaming from a provider client.

    Args:
        client: Provider client with a stream() method.
        request: The LLM request to stream.

    Yields:
        SSE data lines as bytes.
    """
    async for token in client.stream(request):
        chunk = {
            "choices": [{"delta": {"content": token}, "finish_reason": None}]
        }
        yield f"data: {json.dumps(chunk)}\n\n"
    yield "data: [DONE]\n\n"


def _to_openai_format(response: LLMResponse) -> dict[str, Any]:
    """Converts an LLMResponse to OpenAI-compatible JSON format.

    Args:
        response: Normalised LLMResponse from a provider client.

    Returns:
        Dict matching the OpenAI chat.completion response schema.
    """
    return {
        "id": f"chatcmpl-{response.request_id[:8]}",
        "object": "chat.completion",
        "model": response.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": response.content},
                "finish_reason": "stop",
            }
        ],
        "usage": response.usage,
    }
