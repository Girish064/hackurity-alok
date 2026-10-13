"""
tests/conftest.py
Shared pytest fixtures for all test layers.

Unit tests: use fakeredis (no real Redis needed).
Integration tests: use testcontainers (real PostgreSQL + Redis).
"""
from __future__ import annotations

import asyncio
import hashlib
import secrets
import uuid
from collections.abc import AsyncGenerator
from typing import Any

import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from httpx import ASGITransport, AsyncClient

# ── Key fixtures ───────────────────────────────────────────────────────────


@pytest.fixture(scope="session")
def ed25519_key_pair():
    """Generate a fresh Ed25519 key pair for the test session."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


@pytest.fixture(scope="session")
def signing_key(ed25519_key_pair):
    return ed25519_key_pair[0]


@pytest.fixture(scope="session")
def verifying_key(ed25519_key_pair):
    return ed25519_key_pair[1]


# ── fakeredis fixture (unit tests) ─────────────────────────────────────────


@pytest_asyncio.fixture
async def fake_redis():
    """In-memory Redis substitute for unit tests."""
    import fakeredis.aioredis as fakeredis
    r = fakeredis.FakeRedis()
    yield r
    await r.aclose()


# ── In-memory SQLite async DB (unit tests) ────────────────────────────────


@pytest_asyncio.fixture
async def sqlite_session():
    """Async SQLite session for unit tests (no PostgreSQL needed)."""
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from backend.storage.database import Base
    import backend.storage.models  # noqa: ensure models registered

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with factory() as session:
        yield session
    await engine.dispose()


# ── Test agent helpers ─────────────────────────────────────────────────────


def make_api_key() -> tuple[str, str]:
    """Return (raw_key, hashed_key)."""
    raw = secrets.token_urlsafe(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


# ── Test app client fixture ────────────────────────────────────────────────


@pytest_asyncio.fixture
async def test_client(signing_key, verifying_key):
    """
    FastAPI test client with fakeredis and SQLite in-memory DB.
    Overrides settings to use test keys and in-memory storage.
    """
    import fakeredis.aioredis as fakeredis
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

    from backend.main import create_app
    from backend.storage.database import Base, init_engine
    import backend.storage.models  # noqa

    # Override engine with SQLite in-memory
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    fake_r = fakeredis.FakeRedis()

    # Patch dependencies
    from backend import dependencies as deps
    from backend.config import get_settings
    from backend.storage.database import get_session
    from backend.storage.redis_client import get_redis

    settings = get_settings()
    settings._signing_key = signing_key
    settings._verifying_key = verifying_key

    app = create_app()

    async def override_session():
        async with factory() as s:
            try:
                yield s
                await s.commit()
            except Exception:
                await s.rollback()
                raise

    async def override_redis():
        return fake_r

    app.dependency_overrides[get_session] = override_session
    app.dependency_overrides[get_redis] = override_redis

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client

    await fake_r.aclose()
    await engine.dispose()
