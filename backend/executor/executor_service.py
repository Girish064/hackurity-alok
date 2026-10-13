"""
backend/executor/executor_service.py
The core protected executor — the independent authorization enforcement boundary.

This executor independently re-verifies EVERYTHING before running any tool.
It does NOT trust that the gateway behaved correctly.

Execution pipeline (all checks must pass; fail-closed on any error):
  1. Re-canonicalize and re-compute action digest from submitted parameters.
  2. verify_capability() — Ed25519 signature, binding claims, expiry.
  3. Check agent kill-switch in Redis.
  4. Atomically consume the capability (Redis SET NX EX).
  5. Execute the mock tool.
  6. Sign the execution receipt.
  7. Write the execution record to PostgreSQL.
  8. Append the audit event.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

import security as sec
from backend.auth.agent_auth import REDIS_REVOKED_PREFIX
from backend.config import get_settings
from backend.exceptions import (
    ActionDigestMismatchError,
    AgentRevokedError,
    CapabilityConsumedError,
    CapabilityVerificationError,
    ExecutorBindingError,
    SecurityModuleError,
    StorageError,
)
from backend.executor.mock_tools.refund_tool import TOOL_REGISTRY
from backend.executor.replay_guard import consume_capability
from backend.executor.schemas import ExecuteRequest, ExecuteResponse
from backend.services.audit_service import append_event
from backend.storage.models.execution import Execution


async def execute_action(
    session: AsyncSession,
    redis: aioredis.Redis,
    request: ExecuteRequest,
) -> ExecuteResponse:
    """
    Execute a previously authorized action.

    SECURITY CONTRACT: Every check below MUST pass before the tool runs.
    If any check raises an exception the function returns without running the tool.
    """
    settings = get_settings()
    now_utc = datetime.now(timezone.utc)

    # ── Step 1: Re-canonicalize and re-compute action digest ──────────────
    #
    # The agent must present the EXACT same parameters used to request the
    # capability. Any change — even whitespace — produces a different digest
    # and the capability binding check below will reject it.
    try:
        import jwt as _jwt
        from jwt.exceptions import PyJWTError
        unverified = _jwt.decode(
            request.capability_token,
            options={"verify_signature": False, "verify_exp": False},
        )
    except Exception as exc:
        raise CapabilityVerificationError(
            f"Capability token is malformed: {exc}"
        ) from exc

    agent_id_claim = unverified.get("sub", "")
    tenant_id_claim = unverified.get("tenant_id", "")
    expected_digest_from_token = unverified.get("action_digest", "")
    cap_id_claim = unverified.get("jti", "")

    try:
        cap_uuid = uuid.UUID(cap_id_claim)
    except (ValueError, TypeError, AttributeError) as exc:
        raise CapabilityVerificationError("Malformed capability ID in token.") from exc

    # Look up the action request associated with this capability
    from sqlalchemy import select
    from backend.storage.models.action_request import ActionRequest as AR
    ar_result = await session.execute(
        select(AR).where(AR.capability_id == cap_uuid)
    )
    ar = ar_result.scalar_one_or_none()

    if ar is None:
        raise CapabilityVerificationError(
            "Capability not associated with any recorded action request."
        )

    sub_at = ar.submitted_at
    if isinstance(sub_at, datetime):
        if sub_at.tzinfo is None:
            sub_at = sub_at.replace(tzinfo=timezone.utc)
        submitted_at_str = sub_at.isoformat()
    else:
        submitted_at_str = str(sub_at)

    # Re-build the ActionRequest with the presented parameters + token/DB context
    sec_action_full = sec.ActionRequest(
        agent_id=agent_id_claim,
        tenant_id=tenant_id_claim,
        action_type=request.action_type,
        parameters=request.parameters,
        request_id=str(ar.id),
        submitted_at=submitted_at_str,
    )

    try:
        canonical_bytes = sec.canonicalize_action(sec_action_full)
        recomputed_digest = sec.calculate_action_digest(canonical_bytes)
    except sec.CanonicalizationError as exc:
        raise SecurityModuleError(f"Re-canonicalization failed: {exc}") from exc

    if recomputed_digest != expected_digest_from_token:
        raise ActionDigestMismatchError(
            "Re-computed action digest does not match the capability's digest. "
            "The action parameters may have been tampered with."
        )

    # ── Step 2: Full capability verification (signature + all binding claims) ─
    try:
        claims = sec.verify_capability(
            token=request.capability_token,
            expected_agent_id=agent_id_claim,
            expected_tenant_id=tenant_id_claim,
            expected_action_digest=recomputed_digest,
            expected_executor_id=settings.agentshield_executor_id,
            verifying_key=settings.verifying_key,
        )
    except sec.CapabilityExpiredError as exc:
        from backend.exceptions import CapabilityExpiredError
        raise CapabilityExpiredError(str(exc)) from exc
    except sec.CapabilityVerificationError as exc:
        raise CapabilityVerificationError(str(exc)) from exc
    except Exception as exc:
        raise SecurityModuleError(
            f"Unexpected error during capability verification: {exc}"
        ) from exc

    # ── Step 3: Agent kill-switch check (independent of DB) ──────────────
    kill_key = f"{REDIS_REVOKED_PREFIX}{claims.agent_id}"
    is_killed = await redis.exists(kill_key)
    if is_killed:
        raise AgentRevokedError(
            f"Agent {claims.agent_id!r} is subject to the kill switch. "
            "Execution rejected."
        )

    # ── Step 4: Atomic capability consumption ─────────────────────────────
    # This is the replay prevention gate. SET key NX EX is atomic.
    await consume_capability(
        redis,
        claims.capability_id,
        settings.consumed_capability_ttl_seconds,
    )

    # ── Step 5: Resolve and execute the mock tool ─────────────────────────
    tool = TOOL_REGISTRY.get(request.action_type.upper())
    if tool is None:
        # Capability was consumed; we cannot re-run — record failure.
        outcome = "tool_error"
        outcome_data = {"error": f"Unknown action_type: {request.action_type!r}"}
        tool_name = "unknown"
    else:
        tool_name = tool.tool_name
        try:
            tool_result = await tool.execute(request.parameters)
            outcome = tool_result.outcome
            outcome_data = tool_result.data
        except Exception as exc:
            outcome = "tool_error"
            outcome_data = {"error": f"Tool raised an exception: {exc}"}

    executed_at = datetime.now(timezone.utc).isoformat()

    # ── Step 6: Sign execution receipt ────────────────────────────────────
    try:
        receipt_token = sec.sign_execution_receipt(
            capability_id=claims.capability_id,
            action_digest=claims.action_digest,
            executor_id=settings.agentshield_executor_id,
            outcome=outcome.upper(),
            outcome_data=outcome_data,
            executed_at=executed_at,
            signing_key=settings.signing_key,
            key_id=settings.agentshield_key_id,
        )
    except Exception as exc:
        receipt_token = ""  # receipt failure must not block persistence
        outcome_data["receipt_error"] = str(exc)

    # ── Step 7: Persist execution record ─────────────────────────────────
    execution_id = uuid.uuid4()
    execution = Execution(
        id=execution_id,
        action_request_id=None,          # FK lookup can be done async if needed
        capability_id=uuid.UUID(claims.capability_id),
        agent_id=uuid.UUID(claims.agent_id),
        tenant_id=uuid.UUID(claims.tenant_id),
        tool_name=tool_name,
        parameters_snapshot=request.parameters,
        action_digest=claims.action_digest,
        outcome=outcome,
        outcome_data=outcome_data,
        receipt_token=receipt_token,
        executed_at=datetime.fromisoformat(executed_at),
    )

    if ar:
        execution.action_request_id = ar.id
        ar.status = "executed"

    session.add(execution)
    await session.flush()

    # ── Step 8: Append audit event ────────────────────────────────────────
    await append_event(
        session,
        event_type=f"EXECUTION_{outcome.upper()}",
        event_data={
            "execution_id": str(execution_id),
            "capability_id": claims.capability_id,
            "agent_id": claims.agent_id,
            "action_type": request.action_type,
            "action_digest": claims.action_digest,
            "tool_name": tool_name,
            "outcome": outcome,
            "executed_at": executed_at,
        },
        actor_id=claims.agent_id,
    )

    return ExecuteResponse(
        execution_id=str(execution_id),
        outcome=outcome,
        outcome_data=outcome_data,
        receipt_token=receipt_token,
        executed_at=executed_at,
    )
