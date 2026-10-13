"""
backend/dependencies.py
FastAPI dependency providers for DB sessions, Redis, keys, and settings.
"""
from __future__ import annotations

from collections.abc import AsyncGenerator

import redis.asyncio as aioredis
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.config import Settings, get_settings
from backend.storage.database import get_session
from backend.storage.redis_client import get_redis


async def db_session(
    session: AsyncSession = Depends(get_session),
) -> AsyncGenerator[AsyncSession, None]:
    """Yield an async DB session for the current request."""
    yield session


async def redis_client(
    redis: aioredis.Redis = Depends(get_redis),
) -> aioredis.Redis:
    """Return the shared async Redis client."""
    return redis


def settings_dep() -> Settings:
    """Return the cached application settings."""
    return get_settings()


def signing_key_dep(settings: Settings = Depends(settings_dep)) -> Ed25519PrivateKey:
    """Return the Ed25519 signing key."""
    return settings.signing_key


def verifying_key_dep(settings: Settings = Depends(settings_dep)) -> Ed25519PublicKey:
    """Return the Ed25519 verifying key."""
    return settings.verifying_key
