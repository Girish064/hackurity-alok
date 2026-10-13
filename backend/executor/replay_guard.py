"""
backend/executor/replay_guard.py
Redis atomic capability consumption for replay prevention.

CRITICAL: Uses SET key NX EX (atomic) — not GET followed by SET.
Any non-atomic approach would create a race condition under concurrent
submissions of the same capability.

INVARIANT: A capability can be consumed AT MOST ONCE.
Even if two concurrent requests arrive simultaneously for the same capability,
only one will receive the NX lock; the other will be rejected.
"""
from __future__ import annotations

import redis.asyncio as aioredis

from backend.exceptions import CapabilityConsumedError

CONSUMED_PREFIX = "agentshield:consumed:"


async def consume_capability(
    redis: aioredis.Redis,
    capability_id: str,
    consumed_ttl_seconds: int,
) -> None:
    """
    Atomically mark a capability as consumed.

    Uses SET key NX EX ttl — the NX flag ensures only one client can set the
    key. Any concurrent attempt that fails the NX check raises CapabilityConsumedError.

    Parameters
    ----------
    capability_id : str
        The jti claim from the capability JWT.
    consumed_ttl_seconds : int
        How long to keep the consumed record in Redis (must exceed capability TTL
        to prevent replay via expiry race). Typically capability_TTL + 3600.

    Raises
    ------
    CapabilityConsumedError
        If the capability has already been consumed (or is being concurrently consumed).
    """
    key = f"{CONSUMED_PREFIX}{capability_id}"
    was_set = await redis.set(key, "consumed", nx=True, ex=consumed_ttl_seconds)
    if not was_set:
        raise CapabilityConsumedError(
            f"Capability {capability_id!r} has already been consumed. "
            "Replay attempt rejected."
        )


async def is_consumed(redis: aioredis.Redis, capability_id: str) -> bool:
    """Return True if the capability has been consumed (for informational queries)."""
    key = f"{CONSUMED_PREFIX}{capability_id}"
    return bool(await redis.exists(key))
