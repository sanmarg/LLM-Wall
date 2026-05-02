# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""FastAPI middleware: auth, CORS, rate-limiting, and request logging."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Callable

from fastapi import Request, Response
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from llm_wall.config import get_settings

logger = logging.getLogger(__name__)

# SlowAPI limiter — keyed by remote IP.
limiter = Limiter(key_func=get_remote_address)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Logs every request with timing and response status.

    Adds an ``X-Request-ID`` header to all responses for correlation.
    """

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Processes an HTTP request, logging duration and status.

        Args:
            request: Incoming Starlette request.
            call_next: Next middleware or route handler.

        Returns:
            HTTP response with X-Request-ID header attached.
        """
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        t0 = time.perf_counter()

        response: Response = await call_next(request)

        duration_ms = (time.perf_counter() - t0) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Processing-Time-Ms"] = f"{duration_ms:.1f}"

        logger.info(
            "%s %s → %d (%.1fms) [%s]",
            request.method,
            request.url.path,
            response.status_code,
            duration_ms,
            request_id[:8],
        )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Injects OWASP-recommended security headers into all responses."""

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Adds security headers to the response.

        Args:
            request: Incoming request.
            call_next: Next middleware handler.

        Returns:
            Response with security headers added.
        """
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=()"
        )
        if get_settings().app_env == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response


def configure_cors(app: "FastAPI") -> None:  # type: ignore[name-defined]
    """Adds CORSMiddleware to the FastAPI app using settings.

    Args:
        app: The FastAPI application instance.
    """
    cfg = get_settings()
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[
            "X-Request-ID",
            "X-Processing-Time-Ms",
            "X-Risk-Score",
            "X-Threat-Action",
        ],
    )
    logger.info("CORS configured: origins=%s", cfg.allowed_origins)
