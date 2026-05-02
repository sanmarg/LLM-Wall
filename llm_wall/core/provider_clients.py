# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""Provider client adapters for all supported LLM backends.

Each provider adapts to the internal LLMRequest / LLMResponse schema.
Clients use httpx for async HTTP, with tenacity retry logic.

Supported providers:
    - OpenAI  (and any OpenAI-compatible endpoint)
    - Google Gemini
    - Ollama  (local)
    - NVIDIA NIM  (Kimi 2.5 and other NIM models)
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from llm_wall.config import Settings, get_settings
from llm_wall.models import LLMRequest, LLMResponse, Provider

logger = logging.getLogger(__name__)

_RETRY_KWARGS: dict[str, Any] = dict(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=1, max=8),
    retry=retry_if_exception_type((httpx.TimeoutException, httpx.ConnectError)),
    reraise=True,
)


# ---------------------------------------------------------------------------
# Abstract base
# ---------------------------------------------------------------------------


class BaseLLMClient(ABC):
    """Abstract base class for all LLM provider clients.

    Subclasses implement `complete` and optionally `stream`.
    """

    def __init__(self, settings: Settings | None = None) -> None:
        """Initialises the client with application settings.

        Args:
            settings: Optional Settings override (used in tests).
        """
        self._cfg = settings or get_settings()
        self._http = httpx.AsyncClient(timeout=60.0)

    @abstractmethod
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Sends a completion request to the provider.

        Args:
            request: Normalised LLM request.

        Returns:
            LLMResponse with generated content and metadata.

        Raises:
            httpx.HTTPStatusError: On non-2xx HTTP responses.
            httpx.TimeoutException: When the provider times out.
        """

    async def stream(
        self, request: LLMRequest
    ) -> AsyncIterator[str]:
        """Streams completion tokens from the provider.

        Args:
            request: Normalised LLM request with stream=True.

        Yields:
            Text delta strings as they arrive.

        Raises:
            NotImplementedError: If the provider does not support streaming.
        """
        raise NotImplementedError(
            f"{self.__class__.__name__} does not support streaming."
        )

    async def aclose(self) -> None:
        """Closes the underlying HTTP client."""
        await self._http.aclose()


# ---------------------------------------------------------------------------
# OpenAI Client
# ---------------------------------------------------------------------------


class OpenAIClient(BaseLLMClient):
    """Client for OpenAI and OpenAI-compatible APIs.

    Constructs standard `/v1/chat/completions` requests.
    """

    @retry(**_RETRY_KWARGS)
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Sends a chat completion to OpenAI.

        Args:
            request: Normalised LLM request.

        Returns:
            LLMResponse with content and usage stats.

        Raises:
            httpx.HTTPStatusError: On API errors (4xx / 5xx).
        """
        t0 = time.perf_counter()
        body: dict[str, Any] = {
            "model": request.model or self._cfg.openai_default_model,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in request.messages
            ],
            "temperature": request.temperature,
            "stream": False,
        }
        if request.max_tokens:
            body["max_tokens"] = request.max_tokens

        headers = {
            "Authorization": (
                f"Bearer {self._cfg.openai_api_key.get_secret_value()}"
            ),
            "Content-Type": "application/json",
        }
        url = f"{self._cfg.openai_base_url}/chat/completions"
        resp = await self._http.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        latency_ms = (time.perf_counter() - t0) * 1000

        logger.debug(
            "OpenAI completion: model=%s latency=%.1fms tokens=%s",
            body["model"],
            latency_ms,
            usage.get("total_tokens"),
        )
        return LLMResponse(
            request_id=request.request_id,
            provider=Provider.OPENAI,
            model=body["model"],
            content=content,
            usage=usage,
            latency_ms=latency_ms,
        )

    async def stream(self, request: LLMRequest) -> AsyncIterator[str]:
        """Streams SSE tokens from OpenAI.

        Args:
            request: LLM request with stream=True.

        Yields:
            Token delta strings.
        """
        body: dict[str, Any] = {
            "model": request.model or self._cfg.openai_default_model,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in request.messages
            ],
            "temperature": request.temperature,
            "stream": True,
        }
        headers = {
            "Authorization": (
                f"Bearer {self._cfg.openai_api_key.get_secret_value()}"
            ),
            "Content-Type": "application/json",
        }
        url = f"{self._cfg.openai_base_url}/chat/completions"
        async with self._http.stream(
            "POST", url, json=body, headers=headers
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if line.startswith("data: "):
                    chunk = line[6:]
                    if chunk == "[DONE]":
                        break
                    import json  # pylint: disable=import-outside-toplevel

                    try:
                        delta = (
                            json.loads(chunk)["choices"][0]["delta"].get(
                                "content", ""
                            )
                        )
                        if delta:
                            yield delta
                    except (KeyError, ValueError):
                        continue


# ---------------------------------------------------------------------------
# Gemini Client
# ---------------------------------------------------------------------------


class GeminiClient(BaseLLMClient):
    """Client for Google Gemini via the REST generateContent API."""

    _ROLE_MAP: dict[str, str] = {
        "user": "user",
        "assistant": "model",
        "system": "user",  # Gemini encodes system as first user turn
    }

    @retry(**_RETRY_KWARGS)
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Sends a generation request to Gemini.

        Args:
            request: Normalised LLM request.

        Returns:
            LLMResponse with generated content.

        Raises:
            httpx.HTTPStatusError: On 4xx / 5xx responses.
        """
        t0 = time.perf_counter()
        model = request.model or self._cfg.gemini_default_model
        key = self._cfg.gemini_api_key.get_secret_value()
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent?key={key}"
        )

        contents = []
        for msg in request.messages:
            if msg.role == "system":
                # Prepend system content as a user turn
                contents.append(
                    {"role": "user", "parts": [{"text": msg.content}]}
                )
            else:
                contents.append(
                    {
                        "role": self._ROLE_MAP.get(msg.role, "user"),
                        "parts": [{"text": msg.content}],
                    }
                )

        body: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": request.temperature,
            },
        }
        if request.max_tokens:
            body["generationConfig"]["maxOutputTokens"] = request.max_tokens

        resp = await self._http.post(url, json=body)
        resp.raise_for_status()
        data = resp.json()

        content = (
            data["candidates"][0]["content"]["parts"][0]["text"]
        )
        latency_ms = (time.perf_counter() - t0) * 1000
        usage = data.get("usageMetadata", {})

        logger.debug(
            "Gemini completion: model=%s latency=%.1fms", model, latency_ms
        )
        return LLMResponse(
            request_id=request.request_id,
            provider=Provider.GEMINI,
            model=model,
            content=content,
            usage=usage,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Ollama Client
# ---------------------------------------------------------------------------


class OllamaClient(BaseLLMClient):
    """Client for local Ollama server (OpenAI-compatible /api/chat)."""

    @retry(**_RETRY_KWARGS)
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Sends a chat completion to Ollama.

        Args:
            request: Normalised LLM request.

        Returns:
            LLMResponse with generated content.

        Raises:
            httpx.HTTPStatusError: On non-2xx responses.
            httpx.ConnectError: If Ollama is not running.
        """
        t0 = time.perf_counter()
        model = request.model or self._cfg.ollama_default_model
        url = f"{self._cfg.ollama_base_url}/api/chat"

        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in request.messages
            ],
            "stream": False,
            "options": {"temperature": request.temperature},
        }
        if request.max_tokens:
            body["options"]["num_predict"] = request.max_tokens

        resp = await self._http.post(url, json=body, timeout=120.0)
        resp.raise_for_status()
        data = resp.json()

        content = data["message"]["content"]
        latency_ms = (time.perf_counter() - t0) * 1000
        usage = {
            "prompt_tokens": data.get("prompt_eval_count", 0),
            "completion_tokens": data.get("eval_count", 0),
        }

        logger.debug(
            "Ollama completion: model=%s latency=%.1fms", model, latency_ms
        )
        return LLMResponse(
            request_id=request.request_id,
            provider=Provider.OLLAMA,
            model=model,
            content=content,
            usage=usage,
            latency_ms=latency_ms,
        )

    async def list_models(self) -> list[str]:
        """Lists locally available models from Ollama.

        Returns:
            List of model name strings.
        """
        url = f"{self._cfg.ollama_base_url}/api/tags"
        resp = await self._http.get(url, timeout=10.0)
        resp.raise_for_status()
        return [m["name"] for m in resp.json().get("models", [])]

    async def health_check(self) -> bool:
        """Checks if the Ollama server is reachable.

        Returns:
            True if the server responds, False otherwise.
        """
        try:
            resp = await self._http.get(
                self._cfg.ollama_base_url, timeout=5.0
            )
            return resp.status_code < 500
        except Exception:  # pylint: disable=broad-except
            return False


# ---------------------------------------------------------------------------
# NVIDIA NIM Client
# ---------------------------------------------------------------------------


class NVIDIAClient(BaseLLMClient):
    """Client for NVIDIA NIM API (OpenAI-compatible endpoint).

    Supports Kimi 2.5, Mistral, Llama and other NIM-hosted models.
    Base URL: https://integrate.api.nvidia.com/v1
    """

    @retry(**_RETRY_KWARGS)
    async def complete(self, request: LLMRequest) -> LLMResponse:
        """Sends a chat completion to NVIDIA NIM.

        Args:
            request: Normalised LLM request.

        Returns:
            LLMResponse with generated content.

        Raises:
            httpx.HTTPStatusError: On API errors.
        """
        t0 = time.perf_counter()
        model = request.model or self._cfg.nvidia_default_model
        url = f"{self._cfg.nvidia_base_url}/chat/completions"

        body: dict[str, Any] = {
            "model": model,
            "messages": [
                {"role": m.role, "content": m.content}
                for m in request.messages
            ],
            "temperature": request.temperature,
            "stream": False,
        }
        if request.max_tokens:
            body["max_tokens"] = request.max_tokens

        headers = {
            "Authorization": (
                f"Bearer {self._cfg.nvidia_api_key.get_secret_value()}"
            ),
            "Content-Type": "application/json",
        }
        resp = await self._http.post(url, json=body, headers=headers)
        resp.raise_for_status()
        data = resp.json()

        content = data["choices"][0]["message"]["content"]
        usage = data.get("usage", {})
        latency_ms = (time.perf_counter() - t0) * 1000

        logger.debug(
            "NVIDIA NIM completion: model=%s latency=%.1fms", model, latency_ms
        )
        return LLMResponse(
            request_id=request.request_id,
            provider=Provider.NVIDIA,
            model=model,
            content=content,
            usage=usage,
            latency_ms=latency_ms,
        )


# ---------------------------------------------------------------------------
# Provider Factory
# ---------------------------------------------------------------------------


_CLIENT_MAP: dict[Provider, type[BaseLLMClient]] = {
    Provider.OPENAI: OpenAIClient,
    Provider.GEMINI: GeminiClient,
    Provider.OLLAMA: OllamaClient,
    Provider.NVIDIA: NVIDIAClient,
}

_client_instances: dict[Provider, BaseLLMClient] = {}


def get_client(
    provider: Provider,
    settings: Settings | None = None,
) -> BaseLLMClient:
    """Returns a singleton client instance for the given provider.

    Args:
        provider: The target LLM provider enum value.
        settings: Optional Settings override (used in tests).

    Returns:
        A BaseLLMClient subclass instance.

    Raises:
        ValueError: If the provider is not supported.
    """
    if provider not in _CLIENT_MAP:
        raise ValueError(f"Unsupported provider: {provider!r}")
    if provider not in _client_instances:
        _client_instances[provider] = _CLIENT_MAP[provider](settings)
    return _client_instances[provider]


async def close_all_clients() -> None:
    """Closes all cached provider HTTP clients.

    Should be called on application shutdown.
    """
    for client in _client_instances.values():
        await client.aclose()
    _client_instances.clear()
    logger.info("All provider clients closed.")
