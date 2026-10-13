"""
tests/unit/test_opa_policy.py
Unit tests for the OPA policy client integration.

Tests cover:
- OPA disabled (OPA_URL not set) → skip OPA, continue with Python policy only.
- OPA returns allow → allowed.
- OPA returns deny → request denied.
- OPA returns needs_approval → approval required.
- OPA unreachable → OPAUnavailable raised (caller must deny).
- OPA malformed response → treated as deny.
- OPA unknown result string → treated as deny.
- build_opa_input helper constructs correct structure.

No real OPA server is needed — all HTTP calls are mocked with httpx.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from backend.policy.opa_client import (
    OPADecision,
    OPAResult,
    OPAUnavailable,
    build_opa_input,
    evaluate_opa_async,
    opa_health_check,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_opa_response(result: str, reason: str = "TEST", approval_type: str | None = None) -> dict:
    body: dict = {"result": result, "reason": reason}
    if approval_type:
        body["approval_type"] = approval_type
    return {"result": body}


# ---------------------------------------------------------------------------
# build_opa_input
# ---------------------------------------------------------------------------

class TestBuildOpaInput:
    def test_basic_structure(self):
        inp = build_opa_input(
            action={"tool": "issue_refund", "tenant_id": "t1"},
            agent={"registered": True, "revoked": False, "tenant_id": "t1"},
            resource={"owner_tenant_id": "t1"},
            action_digest="abc123",
        )
        assert inp["action"]["action_digest"] == "abc123"
        assert inp["agent"]["registered"] is True
        assert inp["agent"]["revoked"] is False
        assert inp["resource"]["owner_tenant_id"] == "t1"
        assert "approval" not in inp

    def test_approval_included_when_provided(self):
        approval = {"consumed": False, "decision": "approved", "action_digest": "abc", "tenant_id": "t1"}
        inp = build_opa_input(
            action={"tool": "issue_refund", "tenant_id": "t1"},
            agent={"registered": True, "revoked": False, "tenant_id": "t1"},
            resource={"owner_tenant_id": "t1"},
            action_digest="abc",
            approval=approval,
        )
        assert "approval" in inp
        assert inp["approval"]["valid"] is True
        assert inp["approval"]["consumed"] is False

    def test_consumed_approval_is_invalid(self):
        approval = {"consumed": True, "decision": "approved", "action_digest": "abc", "tenant_id": "t1"}
        inp = build_opa_input(
            action={}, agent={}, resource={}, action_digest="abc", approval=approval,
        )
        assert inp["approval"]["valid"] is False


# ---------------------------------------------------------------------------
# evaluate_opa_async
# ---------------------------------------------------------------------------

class TestEvaluateOpaAsync:
    @pytest.mark.asyncio
    async def test_opa_disabled_raises_unavailable(self):
        """Empty OPA_URL should raise OPAUnavailable immediately."""
        with pytest.raises(OPAUnavailable, match="OPA_URL is not configured"):
            await evaluate_opa_async({}, opa_url="")

    @pytest.mark.asyncio
    async def test_allow_result(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _make_opa_response("allow", "POLICY_ALLOW")
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            decision = await evaluate_opa_async({}, opa_url="http://localhost:8181")

        assert decision.result == OPAResult.ALLOW
        assert decision.is_allowed is True

    @pytest.mark.asyncio
    async def test_deny_result(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _make_opa_response("deny", "AGENT_REVOKED")
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            decision = await evaluate_opa_async({}, opa_url="http://localhost:8181")

        assert decision.result == OPAResult.DENY
        assert decision.is_denied is True
        assert "AGENT_REVOKED" in decision.reason

    @pytest.mark.asyncio
    async def test_needs_approval_result(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _make_opa_response(
            "needs_approval", "APPROVAL_REQUIRED_FOR_AMOUNT", approval_type="manager_approval"
        )
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            decision = await evaluate_opa_async({}, opa_url="http://localhost:8181")

        assert decision.result == OPAResult.NEEDS_APPROVAL
        assert decision.needs_approval is True
        assert decision.approval_type == "manager_approval"

    @pytest.mark.asyncio
    async def test_opa_connection_error_raises_unavailable(self):
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.ConnectError("refused"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            with pytest.raises(OPAUnavailable):
                await evaluate_opa_async({}, opa_url="http://localhost:8181")

    @pytest.mark.asyncio
    async def test_opa_timeout_raises_unavailable(self):
        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(side_effect=httpx.TimeoutException("timeout"))
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            with pytest.raises(OPAUnavailable):
                await evaluate_opa_async({}, opa_url="http://localhost:8181")

    @pytest.mark.asyncio
    async def test_malformed_json_returns_deny(self):
        mock_resp = MagicMock()
        mock_resp.json.side_effect = json.JSONDecodeError("bad", "", 0)
        mock_resp.text = "not json"
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            decision = await evaluate_opa_async({}, opa_url="http://localhost:8181")

        assert decision.result == OPAResult.DENY
        assert "MALFORMED" in decision.reason

    @pytest.mark.asyncio
    async def test_unknown_result_string_returns_deny(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = _make_opa_response("maybe_allow")
        mock_resp.raise_for_status = MagicMock()

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = AsyncMock()
            mock_client.post = AsyncMock(return_value=mock_resp)
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_class.return_value = mock_client

            decision = await evaluate_opa_async({}, opa_url="http://localhost:8181")

        assert decision.result == OPAResult.DENY
        assert "UNKNOWN" in decision.reason


# ---------------------------------------------------------------------------
# opa_health_check
# ---------------------------------------------------------------------------

class TestOpaHealthCheck:
    def test_disabled_when_url_empty(self):
        result = opa_health_check(opa_url="")
        assert result["status"] == "disabled"

    def test_down_when_unreachable(self):
        with patch("httpx.get", side_effect=Exception("refused")):
            result = opa_health_check(opa_url="http://localhost:8181")
        assert result["status"] == "down"
        assert "error" in result
