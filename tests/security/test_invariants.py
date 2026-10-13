"""
tests/security/test_invariants.py
Automated verification of the 12 AgentShield security invariants.

These tests use the full FastAPI test client with fakeredis and SQLite.
They exercise real cryptographic operations via the security stub module.
"""
from __future__ import annotations

import asyncio
import uuid

import fakeredis.aioredis as fakeredis
import pytest
import pytest_asyncio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from httpx import ASGITransport, AsyncClient


# ── Helpers ────────────────────────────────────────────────────────────────

ADMIN_TOKEN = "change-me-in-production"
TENANT_ID = str(uuid.uuid4())


async def register_agent(client, permissions=None, max_refund=1000.0):
    resp = await client.post(
        "/agents",
        json={
            "name": "test-agent",
            "tenant_id": TENANT_ID,
            "permissions": permissions if permissions is not None else ["ISSUE_REFUND"],
            "max_refund_amount": max_refund,
        },
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["id"], data["api_key"]


async def submit_action(client, api_key, params, action_type="ISSUE_REFUND"):
    return await client.post(
        "/gateway/actions/submit",
        json={
            "action_type": action_type,
            "parameters": params,
            "request_id": str(uuid.uuid4()),
        },
        headers={"Authorization": f"Bearer {api_key}"},
    )


async def execute_action(client, capability_token, params, action_type="ISSUE_REFUND"):
    return await client.post(
        "/executor/execute",
        json={
            "capability_token": capability_token,
            "action_type": action_type,
            "parameters": params,
        },
    )


# ── Invariant 1: Every sensitive action passes enforcement ─────────────────


class TestInvariant1_EnforcementBoundary:
    async def test_direct_executor_access_without_valid_token_rejected(self, test_client):
        """Invariant 1 + 7(G): Attempting to call the executor directly without
        a real signed capability must be rejected."""
        resp = await test_client.post(
            "/executor/execute",
            json={
                "capability_token": "invalid.token.here",
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "500.00", "currency": "INR", "order_id": "ORD-001"},
            },
        )
        assert resp.status_code in (403, 422), resp.text


# ── Invariant 2: Valid identity ≠ authorized action ────────────────────────


class TestInvariant2_IdentityNotAuthorization:
    async def test_authenticated_agent_without_permission_denied(self, test_client):
        """Invariant 2: Being authenticated does not mean being authorized."""
        agent_id, api_key = await register_agent(test_client, permissions=[])
        resp = await submit_action(test_client, api_key, {"amount": "500.00", "currency": "INR", "order_id": "ORD-001"})
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "POLICY_DENIED"


# ── Invariant 4 & 5: Capability bound to exact action ─────────────────────


class TestInvariant4_5_DigestBinding:
    async def test_modified_amount_rejected_by_executor(self, test_client):
        """Invariant 4 & 5 (Scenario B): Changing parameters after authorization
        must be detected by the executor's digest re-computation."""
        agent_id, api_key = await register_agent(test_client, max_refund=2000)
        params = {"amount": "500.00", "currency": "INR", "order_id": "ORD-001"}
        resp = await submit_action(test_client, api_key, params)
        assert resp.status_code == 200
        cap_token = resp.json()["capability_token"]

        # Tamper: change amount to 5000
        tampered_params = {"amount": "5000.00", "currency": "INR", "order_id": "ORD-001"}
        exec_resp = await execute_action(test_client, cap_token, tampered_params)
        assert exec_resp.status_code in (403, 400), exec_resp.text


# ── Invariant 7: Capability consumed exactly once ─────────────────────────


class TestInvariant7_SingleConsumption:
    async def test_valid_refund_executes_once(self, test_client):
        """Invariant 7 (Scenario C): Second use of the same capability must be rejected."""
        agent_id, api_key = await register_agent(test_client, max_refund=2000)
        params = {"amount": "500.00", "currency": "INR", "order_id": "ORD-002"}
        resp = await submit_action(test_client, api_key, params)
        assert resp.status_code == 200
        cap_token = resp.json()["capability_token"]

        # First execution — must succeed
        exec1 = await execute_action(test_client, cap_token, params)
        assert exec1.status_code == 200, exec1.text
        assert exec1.json()["outcome"] == "success"

        # Second execution — must be rejected
        exec2 = await execute_action(test_client, cap_token, params)
        assert exec2.status_code == 409, exec2.text
        assert exec2.json()["error_code"] == "CAPABILITY_ALREADY_CONSUMED"


# ── Invariant 8: Revoked agents rejected ──────────────────────────────────


class TestInvariant8_RevokedAgent:
    async def test_revoked_agent_cannot_submit(self, test_client):
        """Invariant 8 (Scenario E): Revoked agent must be rejected at the gateway."""
        agent_id, api_key = await register_agent(test_client, max_refund=2000)

        # Revoke the agent
        revoke_resp = await test_client.patch(
            f"/agents/{agent_id}/revoke",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert revoke_resp.status_code == 200

        # Attempt to submit an action
        resp = await submit_action(test_client, api_key, {"amount": "100.00", "currency": "INR", "order_id": "ORD-003"})
        assert resp.status_code in (401, 403), resp.text


# ── Invariant 9: Fail closed ───────────────────────────────────────────────


class TestInvariant9_FailClosed:
    async def test_malformed_token_returns_403_not_200(self, test_client):
        """Invariant 9: Any verification failure must fail closed (not 2xx)."""
        resp = await test_client.post(
            "/executor/execute",
            json={
                "capability_token": "eyJhbGciOiJIUzI1NiJ9.e30.FAKE",
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "500.00", "currency": "INR", "order_id": "ORD-004"},
            },
        )
        assert resp.status_code >= 400


# ── Invariant 10: Hard DENY cannot be overridden ──────────────────────────


class TestInvariant10_HardDenyFinal:
    async def test_amount_above_hard_limit_denied(self, test_client):
        """Invariant 10: Hard deny from policy must not be overridden."""
        agent_id, api_key = await register_agent(test_client, max_refund=50000)
        resp = await submit_action(test_client, api_key, {"amount": "15000.00", "currency": "INR", "order_id": "ORD-005"})
        assert resp.status_code == 403
        assert resp.json()["error_code"] == "POLICY_DENIED"


# ── Invariant 1 (Scenario A): Legitimate action executes successfully ──────


class TestScenarioA_LegitimateAction:
    async def test_authorized_refund_executes_and_produces_record(self, test_client):
        """Scenario A: Full authorized flow end-to-end."""
        agent_id, api_key = await register_agent(test_client, max_refund=2000)
        params = {"amount": "500.00", "currency": "INR", "order_id": "ORD-SCENARIO-A"}

        # Submit to gateway
        gw_resp = await submit_action(test_client, api_key, params)
        assert gw_resp.status_code == 200, gw_resp.text
        gw_data = gw_resp.json()
        assert gw_data["decision"] == "ALLOW"
        cap_token = gw_data["capability_token"]

        # Execute
        exec_resp = await execute_action(test_client, cap_token, params)
        assert exec_resp.status_code == 200, exec_resp.text
        exec_data = exec_resp.json()
        assert exec_data["outcome"] == "success"
        assert "execution_id" in exec_data
        assert "receipt_token" in exec_data

        # Check audit trail
        audit_resp = await test_client.get("/audit/events")
        assert audit_resp.status_code == 200
        events = audit_resp.json()
        event_types = [e["event_type"] for e in events]
        assert "CAPABILITY_ISSUED" in event_types
        assert "EXECUTION_SUCCESS" in event_types


# ── Scenario D: Approval workflow end-to-end ──────────────────────────────


class TestScenarioD_ApprovalWorkflow:
    async def test_action_requiring_approval_flow(self, test_client):
        """Scenario D: Full approval flow from requirement to grant to execution."""
        agent_id, api_key = await register_agent(test_client, max_refund=5000)
        params = {"amount": "1500.00", "currency": "INR", "order_id": "ORD-SCENARIO-D"}
        req_id = str(uuid.uuid4())

        # 1. Submit action requiring approval
        resp = await test_client.post(
            "/gateway/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": params,
                "request_id": req_id,
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "REQUIRE_APPROVAL"
        approval_id = data["approval_id"]
        assert approval_id is not None

        # 2. List pending approvals
        pending_resp = await test_client.get(
            "/approvals",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert pending_resp.status_code == 200
        pending = pending_resp.json()
        assert any(a["id"] == approval_id for a in pending)

        # 3. Admin decides approval
        decide_resp = await test_client.post(
            f"/approvals/{approval_id}/decide",
            json={"decision": "approved", "decided_by": "admin@example.com"},
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert decide_resp.status_code == 200
        assert decide_resp.json()["status"] == "approved"

        # 4. Agent re-submits with original request_id
        resubmit_resp = await test_client.post(
            "/gateway/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": params,
                "request_id": req_id,
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert resubmit_resp.status_code == 200
        resubmit_data = resubmit_resp.json()
        assert resubmit_data["decision"] == "ALLOW"
        cap_token = resubmit_data["capability_token"]

        # 5. Execute action
        exec_resp = await execute_action(test_client, cap_token, params)
        assert exec_resp.status_code == 200
        exec_data = exec_resp.json()
        assert exec_data["outcome"] == "success"

        # 6. Verify audit hash chain
        chain_resp = await test_client.post(
            "/audit/verify-chain",
            headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
        )
        assert chain_resp.status_code == 200
        assert chain_resp.json()["valid"] is True
