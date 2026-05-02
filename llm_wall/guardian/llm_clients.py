# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Thin LLM client wrappers used exclusively by the Guardian engine.

These wrappers are intentionally lightweight — they call the provider
clients with a fixed structured-output prompt and parse the JSON response.
They are separate from the main provider_clients to avoid coupling the
Guardian to the full request pipeline.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

from llm_wall.config import get_settings
from llm_wall.models import ChatMessage, LLMRequest, Provider

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analysis AI. Respond ONLY with valid JSON matching "
    "the schema provided. Do not add markdown fences or commentary."
)


async def _call_ollama(prompt: str, schema_hint: str) -> dict[str, Any]:
    """Calls Ollama with a JSON-mode security analysis prompt.

    Args:
        prompt: The security analysis prompt.
        schema_hint: JSON schema description appended to system prompt.

    Returns:
        Parsed JSON dict from the model response.

    Raises:
        ValueError: If the response cannot be parsed as JSON.
        httpx.RequestError: On network failure.
    """
    cfg = get_settings()
    url = f"{cfg.ollama_base_url}/api/chat"
    body = {
        "model": cfg.ollama_default_model,
        "messages": [
            {"role": "system", "content": f"{_SYSTEM_PROMPT}\n{schema_hint}"},
            {"role": "user", "content": prompt},
        ],
        "stream": False,
        "format": "json",
        "options": {"temperature": 0.0},
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()
    raw = resp.json()["message"]["content"]
    return json.loads(raw)


async def _call_openai(prompt: str, schema_hint: str) -> dict[str, Any]:
    """Calls OpenAI with a JSON-mode security analysis prompt.

    Args:
        prompt: Security analysis prompt.
        schema_hint: JSON schema hint for the model.

    Returns:
        Parsed JSON dict.

    Raises:
        ValueError: On JSON parse failure.
    """
    cfg = get_settings()
    url = f"{cfg.openai_base_url}/chat/completions"
    headers = {
        "Authorization": (
            f"Bearer {cfg.openai_api_key.get_secret_value()}"
        ),
        "Content-Type": "application/json",
    }
    body = {
        "model": cfg.openai_default_model,
        "messages": [
            {"role": "system", "content": f"{_SYSTEM_PROMPT}\n{schema_hint}"},
            {"role": "user", "content": prompt},
        ],
        "response_format": {"type": "json_object"},
        "temperature": 0.0,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
    raw = resp.json()["choices"][0]["message"]["content"]
    return json.loads(raw)


async def _call_gemini(prompt: str, schema_hint: str) -> dict[str, Any]:
    """Calls Gemini with a structured security analysis prompt.

    Args:
        prompt: Security analysis prompt.
        schema_hint: JSON schema hint.

    Returns:
        Parsed JSON dict.

    Raises:
        ValueError: On JSON parse failure.
    """
    cfg = get_settings()
    model = cfg.gemini_default_model
    key = cfg.gemini_api_key.get_secret_value()
    url = (
        f"https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent?key={key}"
    )
    body: dict[str, Any] = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {
                        "text": (
                            f"{_SYSTEM_PROMPT}\n{schema_hint}\n\n{prompt}"
                        )
                    }
                ],
            }
        ],
        "generationConfig": {"temperature": 0.0},
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=body)
        resp.raise_for_status()
    raw = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
    # Strip potential markdown fences
    raw = raw.strip().strip("```json").strip("```").strip()
    return json.loads(raw)


async def _call_nvidia(prompt: str, schema_hint: str) -> dict[str, Any]:
    """Calls NVIDIA NIM with a JSON security analysis prompt.

    Args:
        prompt: Security analysis prompt.
        schema_hint: JSON schema hint.

    Returns:
        Parsed JSON dict.

    Raises:
        ValueError: On JSON parse failure.
    """
    cfg = get_settings()
    url = f"{cfg.nvidia_base_url}/chat/completions"
    headers = {
        "Authorization": (
            f"Bearer {cfg.nvidia_api_key.get_secret_value()}"
        ),
        "Content-Type": "application/json",
    }
    body = {
        "model": cfg.nvidia_default_model,
        "messages": [
            {"role": "system", "content": f"{_SYSTEM_PROMPT}\n{schema_hint}"},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.0,
    }
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=body, headers=headers)
        resp.raise_for_status()
    raw = resp.json()["choices"][0]["message"]["content"]
    raw = raw.strip().strip("```json").strip("```").strip()
    return json.loads(raw)


_PROVIDER_CALLERS = {
    "ollama": _call_ollama,
    "openai": _call_openai,
    "gemini": _call_gemini,
    "nvidia": _call_nvidia,
}


async def call_analysis_llm(
    prompt: str,
    schema_hint: str,
    provider: str | None = None,
) -> dict[str, Any]:
    """Dispatches a Guardian analysis call to the configured provider.

    Falls back to Ollama if the configured provider key is missing.

    Args:
        prompt: The analysis prompt.
        schema_hint: JSON schema description to guide the model.
        provider: Optional provider override ('ollama', 'openai', etc.).

    Returns:
        Parsed JSON response dict.

    Raises:
        RuntimeError: If all provider calls fail.
    """
    cfg = get_settings()
    target = provider or cfg.guardian_analysis_provider
    caller = _PROVIDER_CALLERS.get(target, _call_ollama)
    try:
        result = await caller(prompt, schema_hint)
        logger.debug(
            "Guardian LLM call succeeded: provider=%s", target
        )
        return result
    except Exception as exc:  # pylint: disable=broad-except
        logger.warning(
            "Guardian LLM call failed (provider=%s): %s. "
            "Falling back to Ollama.",
            target,
            exc,
        )
        if target != "ollama":
            return await _call_ollama(prompt, schema_hint)
        raise RuntimeError(
            f"Guardian LLM call failed on all providers: {exc}"
        ) from exc
