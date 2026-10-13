"""
backend/gateway/gateway_service.py
Orchestrates the full gateway pipeline:
  auth → rate-limit → schema validation → policy → canonicalize → issue_capability

This service returns either:
  - A signed capability token (ALLOW)
  - An approval reference (REQUIRE_APPROVAL)
  - Raises PolicyDeniedError (DENY)
"""
from __future__ import annotations

import logging
import os
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

import security as sec
from backend.config import get_settings
from backend.exceptions import (
    DuplicateRequestError,
    PolicyDeniedError,
    SecurityModuleError,
)
from backend.gateway.rate_limiter import check_rate_limit
from backend.gateway.schemas import ActionSubmitRequest
from backend.policy.engine import evaluate
from backend.policy.models import Decision, PolicyDecision
from backend.policy.opa_client import (
    OPAResult,
    OPAUnavailable,
    build_opa_input,
    evaluate_opa_async,
)
from backend.services.approval_service import (
    create_approval_request,
    get_approval_for_action,
)
from backend.services.audit_service import append_event
from backend.storage.models.action_request import ActionRequest
from backend.storage.models.agent import Agent


async def submit_action(
    session: AsyncSession,
    redis: aioredis.Redis,
    agent: Agent,
    request: ActionSubmitRequest,
) -> dict:
    """
    Process an action submission through the full gateway pipeline.

    Returns a dict with keys: decision, and either
      {capability_token, action_digest, expires_at} or {approval_id}.

    Raises:
      PolicyDeniedError — hard policy denial
      DuplicateRequestError — idempotent repeat with same request_id
    """
    settings = get_settings()
    request_id_str = str(request.request_id)

    # ── 1. Rate limiting ──────────────────────────────────────────────────
    await check_rate_limit(redis, str(agent.id))

    # ── 2. Idempotency: check for existing action_request ─────────────────
    existing = await session.execute(
        select(ActionRequest).where(ActionRequest.id == request.request_id)
    )
    existing_record: ActionRequest | None = existing.scalar_one_or_none()

    if existing_record is not None:
        # Return the original decision without re-evaluating
        return _build_response_from_existing(existing_record)

    # ── 3. Policy evaluation ──────────────────────────────────────────────
    policy_result = evaluate(
        agent=agent,
        action_type=request.action_type,
        parameters=request.parameters,
    )

    # ── 3b. Optional OPA policy check (additive, fail-closed) ────────────
    # OPA is only consulted when OPA_URL is set; otherwise Python-only.
    # Fail-closed: OPA unavailable / error → deny immediately.
    # Both engines must agree to allow; OPA DENY overrides Python ALLOW.
    # OPA NEEDS_APPROVAL escalates even when Python said ALLOW.
    opa_url = os.environ.get("OPA_URL", "")
    if opa_url:
        _log = logging.getLogger(__name__)
        _opa_input = build_opa_input(
            action={
                "tool": request.action_type.lower(),
                "tenant_id": str(agent.tenant_id),
                "environment": "demo",
                "policy_version": 2,
                "arguments": request.parameters or {},
            },
            agent={
                "registered": True,
                "revoked": False,
                "tenant_id": str(agent.tenant_id),
                "permitted_tools": list(agent.permissions or []),
            },
            resource={"owner_tenant_id": str(agent.tenant_id)},
            action_digest="",  # digest not yet computed; OPA gets it after
        )
        try:
            _opa_decision = await evaluate_opa_async(_opa_input, opa_url=opa_url)
            if _opa_decision.result == OPAResult.DENY:
                _log.warning(
                    "OPA denied action for agent %s: %s",
                    agent.id,
                    _opa_decision.reason,
                )
                raise PolicyDeniedError(
                    f"OPA denied: {_opa_decision.reason}",
                    request_id=request_id_str,
                )
            if _opa_decision.result == OPAResult.NEEDS_APPROVAL:
                if policy_result.decision == Decision.ALLOW:
                    _log.info(
                        "OPA requires approval for agent %s: %s",
                        agent.id,
                        _opa_decision.reason,
                    )
                    policy_result = PolicyDecision(
                        decision=Decision.REQUIRE_APPROVAL,
                        reason=f"OPA requires approval: {_opa_decision.reason}",
                    )
            # OPA.ALLOW → continue with Python policy result unchanged
        except OPAUnavailable as exc:
            _log.error("OPA unavailable — failing closed: %s", exc)
            raise PolicyDeniedError(
                f"Policy check unavailable (OPA): {exc}",
                request_id=request_id_str,
            ) from exc

    # ── 4. Build the canonical ActionRequest for the security module ──────
    submitted_at = datetime.now(timezone.utc).isoformat()
    sec_action = sec.ActionRequest(
        agent_id=str(agent.id),
        tenant_id=str(agent.tenant_id),
        action_type=request.action_type,
        parameters=request.parameters,
        request_id=request_id_str,
        submitted_at=submitted_at,
    )

    # ── 5. Canonicalize and compute digest (always, for audit purposes) ───
    try:
        canonical_bytes = sec.canonicalize_action(sec_action)
        action_digest = sec.calculate_action_digest(canonical_bytes)
    except sec.CanonicalizationError as exc:
        raise SecurityModuleError(
            f"Action canonicalization failed: {exc}"
        ) from exc

    # ── 6. Handle DENY ────────────────────────────────────────────────────
    if policy_result.decision == Decision.DENY:
        # Persist the denied record for audit purposes
        ar = ActionRequest(
            id=request.request_id,
            agent_id=agent.id,
            tenant_id=agent.tenant_id,
            action_type=request.action_type,
            parameters=request.parameters,
            action_digest=action_digest,
            policy_decision="DENY",
            status="denied",
            submitted_at=datetime.fromisoformat(submitted_at),
        )
        session.add(ar)
        await session.flush()

        await append_event(
            session,
            event_type="ACTION_DENIED",
            event_data={
                "request_id": request_id_str,
                "agent_id": str(agent.id),
                "action_type": request.action_type,
                "reason": policy_result.reason,
            },
            actor_id=str(agent.id),
        )
        raise PolicyDeniedError(policy_result.reason, request_id=request_id_str)

    # ── 7. Handle REQUIRE_APPROVAL ────────────────────────────────────────
    if policy_result.decision == Decision.REQUIRE_APPROVAL:
        ar = ActionRequest(
            id=request.request_id,
            agent_id=agent.id,
            tenant_id=agent.tenant_id,
            action_type=request.action_type,
            parameters=request.parameters,
            action_digest=action_digest,
            policy_decision="REQUIRE_APPROVAL",
            status="awaiting_approval",
            submitted_at=datetime.fromisoformat(submitted_at),
        )
        session.add(ar)
        await session.flush()

        approval = await create_approval_request(session, ar, action_digest)

        await append_event(
            session,
            event_type="APPROVAL_REQUESTED",
            event_data={
                "request_id": request_id_str,
                "approval_id": str(approval.id),
                "agent_id": str(agent.id),
                "action_type": request.action_type,
                "action_digest": action_digest,
                "reason": policy_result.reason,
            },
            actor_id=str(agent.id),
        )
        return {
            "decision": "REQUIRE_APPROVAL",
            "request_id": request_id_str,
            "approval_id": str(approval.id),
            "message": policy_result.reason,
        }

    # ── 8. ALLOW: check if approval is needed (re-submitted after approval) ─
    # If an existing approval is already approved, issue the capability.
    # (This path handles the agent re-submitting the same request_id after approval.)
    # For fresh ALLOW decisions, issue immediately.

    # ── 9. Issue capability ───────────────────────────────────────────────
    try:
        cap = sec.issue_capability(
            agent_id=str(agent.id),
            tenant_id=str(agent.tenant_id),
            action_digest=action_digest,
            executor_id=settings.agentshield_executor_id,
            ttl_seconds=settings.capability_ttl_seconds,
            approval_ref=None,
            signing_key=settings.signing_key,
            key_id=settings.agentshield_key_id,
        )
    except Exception as exc:
        raise SecurityModuleError(
            f"Capability issuance failed: {exc}"
        ) from exc

    ar = ActionRequest(
        id=request.request_id,
        agent_id=agent.id,
        tenant_id=agent.tenant_id,
        action_type=request.action_type,
        parameters=request.parameters,
        action_digest=action_digest,
        policy_decision="ALLOW",
        capability_token=cap.token,
        capability_id=uuid.UUID(cap.capability_id),
        expires_at=datetime.fromisoformat(cap.expires_at),
        status="capability_issued",
        submitted_at=datetime.fromisoformat(submitted_at),
    )
    session.add(ar)
    await session.flush()

    await append_event(
        session,
        event_type="CAPABILITY_ISSUED",
        event_data={
            "request_id": request_id_str,
            "capability_id": cap.capability_id,
            "agent_id": str(agent.id),
            "action_type": request.action_type,
            "action_digest": action_digest,
            "expires_at": cap.expires_at,
        },
        actor_id=str(agent.id),
    )

    return {
        "decision": "ALLOW",
        "request_id": request_id_str,
        "capability_token": cap.token,
        "action_digest": action_digest,
        "expires_at": cap.expires_at,
    }


async def submit_action_after_approval(
    session: AsyncSession,
    redis: aioredis.Redis,
    agent: Agent,
    request: ActionSubmitRequest,
) -> dict:
    """
    Re-submit path: agent presents the same request_id after approval was granted.
    The gateway issues the capability now that the approval exists.
    """
    settings = get_settings()
    request_id_str = str(request.request_id)

    # Fetch existing action_request (must already exist in awaiting_approval state)
    result = await session.execute(
        select(ActionRequest).where(ActionRequest.id == request.request_id)
    )
    ar: ActionRequest | None = result.scalar_one_or_none()

    if ar is None:
        # First-time submission — route to normal submit
        return await submit_action(session, redis, agent, request)

    if ar.status == "capability_issued":
        return _build_response_from_existing(ar)

    if ar.status != "awaiting_approval":
        return _build_response_from_existing(ar)

    # Check approval
    from backend.services.approval_service import get_approval_for_action
    from backend.exceptions import ApprovalNotFoundError, ApprovalExpiredError
    from backend.storage.models.approval import ApprovalRequest as APR

    approval = await get_approval_for_action(session, str(ar.id))
    if approval is None or approval.status != "approved":
        return {
            "decision": "REQUIRE_APPROVAL",
            "request_id": request_id_str,
            "approval_id": str(approval.id) if approval else None,
            "message": "Action is still awaiting human approval.",
        }

    # Verify approval record integrity and digest binding
    from backend.exceptions import ApprovalVerificationError
    sec_rec = sec.ApprovalRecord(
        approval_id=str(approval.id),
        action_request_id=str(approval.action_request_id),
        agent_id=str(approval.agent_id),
        action_digest=approval.action_digest,
        action_hmac=approval.action_hmac,
        status=approval.status,
        decided_by=approval.decided_by,
        decided_at=approval.decided_at.isoformat() if approval.decided_at else None,
        expires_at=approval.expires_at.isoformat(),
    )
    try:
        sec.verify_approval(
            approval_record=sec_rec,
            action_digest=ar.action_digest,
            approved_by=approval.decided_by or "",
            hmac_secret=settings.admin_secret_token,
        )
    except sec.ApprovalVerificationError as exc:
        raise ApprovalVerificationError(str(exc)) from exc

    # Issue capability with approval reference
    try:
        cap = sec.issue_capability(
            agent_id=str(agent.id),
            tenant_id=str(agent.tenant_id),
            action_digest=ar.action_digest,
            executor_id=settings.agentshield_executor_id,
            ttl_seconds=settings.capability_ttl_seconds,
            approval_ref=str(approval.id),
            signing_key=settings.signing_key,
            key_id=settings.agentshield_key_id,
        )
    except Exception as exc:
        raise SecurityModuleError(
            f"Capability issuance after approval failed: {exc}"
        ) from exc

    ar.capability_token = cap.token
    ar.capability_id = uuid.UUID(cap.capability_id)
    ar.expires_at = datetime.fromisoformat(cap.expires_at)
    ar.status = "capability_issued"
    await session.flush()

    await append_event(
        session,
        event_type="CAPABILITY_ISSUED_AFTER_APPROVAL",
        event_data={
            "request_id": request_id_str,
            "capability_id": cap.capability_id,
            "approval_id": str(approval.id),
            "agent_id": str(agent.id),
            "action_type": ar.action_type,
            "action_digest": ar.action_digest,
        },
        actor_id=str(agent.id),
    )

    return {
        "decision": "ALLOW",
        "request_id": request_id_str,
        "capability_token": cap.token,
        "action_digest": ar.action_digest,
        "expires_at": cap.expires_at,
    }


def _build_response_from_existing(ar: ActionRequest) -> dict:
    """Re-construct the response dict from a previously processed action_request."""
    if ar.status == "denied":
        raise PolicyDeniedError(
            "This request was previously denied.",
            request_id=str(ar.id),
        )
    if ar.status in ("awaiting_approval",):
        return {
            "decision": "REQUIRE_APPROVAL",
            "request_id": str(ar.id),
            "approval_id": None,
            "message": "Action is awaiting human approval.",
        }
    if ar.capability_token:
        return {
            "decision": "ALLOW",
            "request_id": str(ar.id),
            "capability_token": ar.capability_token,
            "action_digest": ar.action_digest,
            "expires_at": ar.expires_at.isoformat() if ar.expires_at else None,
        }
    raise PolicyDeniedError(
        "Could not reconstruct prior decision.",
        request_id=str(ar.id),
    )
