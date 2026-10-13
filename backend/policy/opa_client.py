"""
backend/policy/opa_client.py
OPA Policy Client — wraps OPA HTTP API calls.

Owner: Pavan (design)

Fail-closed: OPA unavailable -> raise PolicyCheckUnavailable (caller denies).
Unknown / malformed OPA result -> treated as deny.

Usage
-----
Set the environment variable ``OPA_URL`` (default: empty / disabled).
When ``OPA_URL`` is empty the caller skips OPA and uses only the Python policy.
When ``OPA_URL`` is set, OPA must agree (allow) for the request to proceed.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

import httpx

log = logging.getLogger(__name__)

# Read from environment; empty string means "OPA disabled".
OPA_URL: str = os.environ.get("OPA_URL", "")
OPA_POLICY_PATH: str = "agentshield/authz/decision"
OPA_TIMEOUT_SECONDS: float = 5.0


# ---------------------------------------------------------------------------
# Decision types
# ---------------------------------------------------------------------------

class OPAResult(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NEEDS_APPROVAL = "needs_approval"


@dataclass
class OPADecision:
    result: OPAResult
    reason: str
    approval_type: Optional[str] = None

    @property
    def is_allowed(self) -> bool:
        return self.result == OPAResult.ALLOW

    @property
    def is_denied(self) -> bool:
        return self.result == OPAResult.DENY

    @property
    def needs_approval(self) -> bool:
        return self.result == OPAResult.NEEDS_APPROVAL


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class OPAUnavailable(Exception):
    """OPA is unreachable or timed out.  Caller must fail closed (deny)."""


# ---------------------------------------------------------------------------
# Input builder
# ---------------------------------------------------------------------------

def build_opa_input(
    *,
    action: dict[str, Any],
    agent: dict[str, Any],
    resource: dict[str, Any],
    action_digest: str,
    approval: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Build the OPA input document for policy evaluation.

    Args:
        action:        The action envelope (dict).
        agent:         Agent record (registered, revoked, tenant_id, permitted_tools, …).
        resource:      Resource ownership record (owner_tenant_id).
        action_digest: Pre-computed hex action digest.
        approval:      Approval record, if one has been submitted (optional).

    Returns:
        OPA input dict ready for POST /v1/data/{path}.
    """
    opa_action = dict(action)
    opa_action["action_digest"] = action_digest

    inp: dict[str, Any] = {
        "action": opa_action,
        "agent": {
            "registered": agent.get("registered", False),
            "revoked": agent.get("revoked", False),
            "tenant_id": agent.get("tenant_id", ""),
            "permitted_tools": agent.get("permitted_tools", []),
            "max_amount_minor": agent.get("max_amount_minor"),
        },
        "resource": {
            "owner_tenant_id": resource.get("owner_tenant_id", ""),
        },
    }

    if approval is not None:
        inp["approval"] = {
            "valid": (
                not approval.get("consumed", True)
                and approval.get("decision") == "approved"
            ),
            "action_digest": approval.get("action_digest", ""),
            "tenant_id": approval.get("tenant_id", ""),
            "consumed": approval.get("consumed", True),
            "decision": approval.get("decision", "rejected"),
        }

    return inp


# ---------------------------------------------------------------------------
# Async OPA client
# ---------------------------------------------------------------------------

async def evaluate_opa_async(
    opa_input: dict[str, Any],
    opa_url: str = "",
    policy_path: str = OPA_POLICY_PATH,
    timeout: float = OPA_TIMEOUT_SECONDS,
) -> OPADecision:
    """
    Async OPA policy evaluation.

    Fail-closed:
    - OPA unreachable / timeout  → raises OPAUnavailable
    - Malformed JSON response     → returns deny
    - Unknown result value        → returns deny

    Args:
        opa_input:   Dict built with build_opa_input().
        opa_url:     OPA server base URL.  If empty, raises OPAUnavailable.
        policy_path: Rego package path for the decision rule.
        timeout:     HTTP timeout (seconds).

    Returns:
        OPADecision

    Raises:
        OPAUnavailable: OPA unreachable or timed out.
    """
    url_base = opa_url or OPA_URL
    if not url_base:
        raise OPAUnavailable("OPA_URL is not configured.")

    url = f"{url_base.rstrip('/')}/v1/data/{policy_path}"

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(url, json={"input": opa_input})
            resp.raise_for_status()
    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError) as exc:
        log.error("OPA unreachable at %s: %s", url, exc)
        raise OPAUnavailable(f"OPA unavailable: {exc}") from exc
    except Exception as exc:
        log.error("OPA unexpected error: %s", exc)
        raise OPAUnavailable(f"OPA unexpected error: {exc}") from exc

    try:
        body = resp.json()
        decision_raw = body.get("result", {})
    except (json.JSONDecodeError, AttributeError) as exc:
        log.error("Malformed OPA response: %s", resp.text[:200])
        # Fail closed — malformed response is treated as deny
        return OPADecision(result=OPAResult.DENY, reason="OPA_MALFORMED_RESPONSE")

    result_str = decision_raw.get("result", "deny")
    reason = decision_raw.get("reason", "DEFAULT_DENY")
    approval_type = decision_raw.get("approval_type")

    try:
        result = OPAResult(result_str)
    except ValueError:
        log.warning("Unknown OPA result value: %r — treating as deny", result_str)
        result = OPAResult.DENY
        reason = f"OPA_UNKNOWN_RESULT:{result_str}"

    return OPADecision(result=result, reason=reason, approval_type=approval_type)


# ---------------------------------------------------------------------------
# Health check (sync, for the /health endpoint)
# ---------------------------------------------------------------------------

def opa_health_check(opa_url: str = "") -> dict[str, str]:
    """Return ``{"status": "up"}`` or ``{"status": "down", "error": "…"}``."""
    url_base = opa_url or OPA_URL
    if not url_base:
        return {"status": "disabled"}
    try:
        resp = httpx.get(f"{url_base.rstrip('/')}/health", timeout=2.0)
        if resp.status_code == 200:
            return {"status": "up"}
        return {"status": "down", "error": f"HTTP {resp.status_code}"}
    except Exception as exc:
        return {"status": "down", "error": str(exc)}
