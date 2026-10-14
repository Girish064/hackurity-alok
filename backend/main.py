"""
backend/main.py
AgentShield V3 FastAPI application factory.

Startup lifecycle:
  1. Initialize PostgreSQL async engine.
  2. Initialize Redis connection pool.
  3. Load active baseline from Redis (defaults to C on first run).
  4. Register all API routers.
  5. Register domain exception handlers.
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import get_settings
from backend.exceptions import register_exception_handlers
from backend.storage.database import close_engine, init_engine
from backend.storage.redis_client import close_redis, init_redis

# ── API routers ───────────────────────────────────────────────────────────
from backend.api.health import router as health_router
from backend.api.agents import router as agents_router
from backend.api.gateway import router as gateway_router
from backend.api.executor import router as executor_router
from backend.api.approvals import router as approvals_router
from backend.api.audit import router as audit_router
# V3 additions
from backend.api.capabilities import router as capabilities_router
from backend.api.actions import router as actions_router
from backend.api.receipts import router as receipts_router
from backend.api.metrics import router as metrics_router
from backend.api.config import router as config_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown."""
    settings = get_settings()
    init_engine(settings.database_url)
    init_redis(settings.redis_url)

    # Load active baseline from Redis (non-fatal if Redis unavailable at import time)
    try:
        from backend.storage.redis_client import get_redis
        from core.baseline import load_baseline_from_redis
        r = await get_redis()
        await load_baseline_from_redis(r)
    except Exception:
        pass  # Baseline defaults to C

    yield
    await close_engine()
    await close_redis()


def create_app() -> FastAPI:
    settings = get_settings()

    # Allow CORS origins to be configured via environment variable
    cors_origins_env = os.environ.get(
        "CORS_ORIGINS",
        "http://localhost:3000,http://localhost:5173,http://localhost:8501",
    )
    cors_origins = [o.strip() for o in cors_origins_env.split(",") if o.strip()]

    app = FastAPI(
        title="AgentShield V3",
        description=(
            "Adaptive Zero-Trust Action Security for AI Agents. "
            "Don't just detect — mathematically guarantee the boundary. "
            "\n\n"
            "Every sensitive action is independently authorized, cryptographically "
            "bound, and audited before execution."
        ),
        version="3.0.0",
        lifespan=lifespan,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ──────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Exception handlers ────────────────────────────────────────────────
    register_exception_handlers(app)

    # ── Routers — original ────────────────────────────────────────────────
    app.include_router(health_router)
    app.include_router(agents_router)
    app.include_router(gateway_router)
    app.include_router(executor_router)
    app.include_router(approvals_router)
    app.include_router(audit_router)

    # ── Routers — V3 additions ────────────────────────────────────────────
    app.include_router(capabilities_router)
    app.include_router(actions_router)
    app.include_router(receipts_router)
    app.include_router(metrics_router)
    app.include_router(config_router)

    return app


app = create_app()
