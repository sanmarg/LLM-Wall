# Copyright 2024 LLM Wall Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License").
"""FastAPI application factory for LLM Wall.

Wires all subsystems together: proxy router, API routers, middleware,
Sentinel node lifecycle, Ledger node lifecycle, and health endpoints.
"""

from __future__ import annotations

import logging
import logging.config
import os
from contextlib import asynccontextmanager
from typing import AsyncIterator

import structlog
import uvicorn
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from llm_wall.api.dashboard_router import router as dashboard_router
from llm_wall.api.ledger_router import router as ledger_router
from llm_wall.api.patterns_router import router as patterns_router
from llm_wall.api.sentinel_router import router as sentinel_router
from llm_wall.guardian.pattern_updater import get_pattern_updater
from llm_wall.config import get_settings
from llm_wall.core.middleware import (
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
    configure_cors,
    limiter,
)
from llm_wall.core.provider_clients import close_all_clients
from llm_wall.core.router import router as proxy_router
from llm_wall.ledger.node import get_ledger_node
from llm_wall.sentinel.node import get_sentinel_node

logger = logging.getLogger(__name__)


def _configure_logging(log_level: str) -> None:
    """Configures structlog + stdlib logging.

    Args:
        log_level: Log level string (debug, info, warning, error).
    """
    level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s %(name)-40s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    # Silence noisy third-party loggers
    for noisy in ("httpx", "httpcore", "uvicorn.access"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifespan: startup and shutdown hooks.

    Args:
        app: The FastAPI application instance.

    Yields:
        Control to FastAPI during the application lifetime.
    """
    cfg = get_settings()
    _configure_logging(cfg.app_log_level)
    logger.info("=" * 60)
    logger.info("LLM Wall %s starting (env=%s)", cfg.app_name, cfg.app_env)
    logger.info("=" * 60)

    # Create data directory
    os.makedirs("./data", exist_ok=True)

    # Start Sentinel Node (background gossip loop)
    sentinel = get_sentinel_node()
    await sentinel.start()

    # Start Ledger Node (background flush loop)
    ledger = get_ledger_node()
    await ledger.start()

    # Start Pattern Updater (auto-evolving threat-intel)
    pattern_updater = get_pattern_updater(
        ioc_store=sentinel.get_ioc_store()
    )
    await pattern_updater.start()

    logger.info("All subsystems started. Ready to intercept LLM traffic.")
    yield

    # Shutdown
    logger.info("LLM Wall shutting down…")
    await pattern_updater.stop()
    await sentinel.stop()
    await ledger.stop()
    await close_all_clients()
    logger.info("LLM Wall shutdown complete.")


def create_app() -> FastAPI:
    """Creates and configures the FastAPI application.

    Returns:
        Configured FastAPI application ready to serve.
    """
    cfg = get_settings()

    app = FastAPI(
        title="LLM Wall — Agentic Security Fabric",
        description=(
            "AI-native semantic firewall for LLM infrastructure. "
            "Intercepts, analyses, and audits every LLM call using "
            "multi-agent Guardian, MARL, Sentinel mesh, and blockchain ledger."
        ),
        version="1.0.0",
        docs_url="/docs" if cfg.app_env != "production" else None,
        redoc_url="/redoc" if cfg.app_env != "production" else None,
        lifespan=_lifespan,
    )

    # Rate limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    # Middleware (applied in LIFO order, so last added = outermost)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    configure_cors(app)

    # Routers
    app.include_router(proxy_router)
    app.include_router(dashboard_router)
    app.include_router(sentinel_router)
    app.include_router(ledger_router)
    app.include_router(patterns_router)

    @app.get("/health", tags=["health"])
    async def health_check() -> JSONResponse:
        """Liveness health check endpoint.

        Returns:
            JSON with status 'ok' and version.
        """
        return JSONResponse(
            content={"status": "ok", "version": "1.0.0", "service": "llm-wall"}
        )

    @app.get("/ready", tags=["health"])
    async def readiness_check() -> JSONResponse:
        """Readiness check — verifies all subsystems are operational.

        Returns:
            JSON with per-system readiness flags.
        """
        sentinel = get_sentinel_node()
        ledger = get_ledger_node()
        chain_valid = ledger.verify_chain()
        return JSONResponse(
            content={
                "ready": chain_valid,
                "sentinel_running": sentinel.get_status()["running"],
                "chain_valid": chain_valid,
                "chain_height": ledger.get_stats()["height"],
            }
        )

    logger.info("FastAPI application created with %d routes.", len(app.routes))
    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

app = create_app()


def main() -> None:
    """Starts the Uvicorn server (used by the CLI entry point).

    Called by ``llm-wall`` console script from pyproject.toml.
    """
    cfg = get_settings()
    uvicorn.run(
        "llm_wall.core.app:app",
        host=cfg.app_host,
        port=cfg.app_port,
        workers=cfg.app_workers,
        log_level=cfg.app_log_level,
        reload=cfg.app_env == "development",
    )


if __name__ == "__main__":
    main()
