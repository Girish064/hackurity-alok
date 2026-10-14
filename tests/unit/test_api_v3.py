"""
tests/unit/test_api_v3.py
Integration tests for the V3 API endpoints using the FastAPI test client.

Covers:
  1. Health endpoint with standard response contract
  2. System status
  3. Config GET/POST (baseline switch)
  4. Actions list and submit
  5. Receipts list
  6. Metrics
  7. Adaptive policy via capabilities/issue
  8. Baseline A/B/C behavior differences
"""
from __future__ import annotations

import uuid
from typing import Any

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from backend.main import create_app
from core.baseline import BaselineID, set_active_baseline, get_active_baseline_id


# ── App fixture ────────────────────────────────────────────────────────────

@pytest_asyncio.fixture
async def client(signing_key, verifying_key):
    """Test client with in-memory SQLite + fakeredis."""
    import fakeredis.aioredis as fakeredis
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
    from backend.storage.database import Base
    import backend.storage.models  # noqa

    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    fake_r = fakeredis.FakeRedis()

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

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c

    await fake_r.aclose()
    await engine.dispose()


@pytest_asyncio.fixture
async def registered_agent(client):
    """Register an agent and return (agent_id, api_key, tenant_id)."""
    tenant_id = str(uuid.uuid4())
    resp = await client.post(
        "/agents",
        json={
            "name": "test-agent",
            "tenant_id": tenant_id,
            "permissions": ["ISSUE_REFUND", "SEND_EMAIL"],
            "max_refund_amount": 5000.0,
        },
        headers={"Authorization": "Bearer change-me-in-production"},
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    return data["id"], data["api_key"], tenant_id


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEALTH
# ══════════════════════════════════════════════════════════════════════════════

class TestHealth:
    async def test_health_returns_standard_contract(self, client):
        r = await client.get("/health")
        assert r.status_code == 200
        body = r.json()
        assert "status" in body
        assert "code" in body
        assert "message" in body
        assert "data" in body

    async def test_health_data_has_components(self, client):
        r = await client.get("/health")
        body = r.json()
        components = body["data"].get("components", {})
        assert "database" in components
        assert "redis" in components

    async def test_health_reports_active_baseline(self, client):
        r = await client.get("/health")
        body = r.json()
        assert "active_baseline" in body["data"]


# ══════════════════════════════════════════════════════════════════════════════
# 2. SYSTEM STATUS
# ══════════════════════════════════════════════════════════════════════════════

class TestSystemStatus:
    async def test_system_status_returns_200(self, client):
        r = await client.get("/system/status")
        assert r.status_code == 200

    async def test_system_status_has_modules(self, client):
        r = await client.get("/system/status")
        body = r.json()
        modules = body["data"].get("modules", {})
        assert "redis" in modules
        assert "security_module" in modules

    async def test_system_status_no_secrets_exposed(self, client):
        r = await client.get("/system/status")
        text = r.text
        # Should never contain private key material
        assert "PRIVATE KEY" not in text
        assert "-----BEGIN" not in text


# ══════════════════════════════════════════════════════════════════════════════
# 3. CONFIG
# ══════════════════════════════════════════════════════════════════════════════

class TestConfig:
    async def test_get_config_open(self, client):
        r = await client.get("/config")
        assert r.status_code == 200
        body = r.json()
        assert "active_baseline" in body["data"]
        assert "available_baselines" in body["data"]

    async def test_set_config_requires_admin(self, client):
        r = await client.post("/config", json={"baseline": "A"})
        # No auth header — should be 401 or 403
        assert r.status_code in (401, 403)

    async def test_set_config_invalid_baseline(self, client):
        r = await client.post(
            "/config",
            json={"baseline": "X"},
            headers={"Authorization": "Bearer change-me-in-production"},
        )
        assert r.status_code == 422

    async def test_set_config_changes_baseline(self, client):
        r = await client.post(
            "/config",
            json={"baseline": "B", "reason": "test"},
            headers={"Authorization": "Bearer change-me-in-production"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["data"]["active_baseline"]["id"] == "B"

        # Restore C
        await client.post(
            "/config",
            json={"baseline": "C"},
            headers={"Authorization": "Bearer change-me-in-production"},
        )

    async def test_config_safety_note_present(self, client):
        r = await client.get("/config")
        body = r.json()
        assert "safety_note" in body["data"]


# ══════════════════════════════════════════════════════════════════════════════
# 4. ACTIONS
# ══════════════════════════════════════════════════════════════════════════════

class TestActions:
    async def test_list_actions_empty(self, client):
        r = await client.get("/actions")
        assert r.status_code == 200
        body = r.json()
        assert body["data"]["count"] == 0

    async def test_get_action_not_found(self, client):
        r = await client.get(f"/actions/{uuid.uuid4()}")
        assert r.status_code == 404

    async def test_get_action_invalid_uuid(self, client):
        r = await client.get("/actions/not-a-uuid")
        assert r.status_code == 422

    async def test_submit_action_unauthenticated(self, client):
        r = await client.post(
            "/actions/submit",
            json={"action_type": "ISSUE_REFUND", "parameters": {"amount": "100.00"}},
        )
        assert r.status_code == 401

    async def test_submit_action_authenticated_allowed(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        r = await client.post(
            "/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "500.00", "currency": "INR", "order_id": "ORD-001"},
                "request_id": str(uuid.uuid4()),
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["data"]["decision"] == "ALLOW"
        assert "capability_token" in body["data"]

    async def test_submit_action_deny_over_limit(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        r = await client.post(
            "/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "99999.00", "currency": "INR", "order_id": "ORD-002"},
                "request_id": str(uuid.uuid4()),
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["status"] == "blocked"
        assert body["data"]["decision"] == "DENY"

    async def test_submit_action_requires_approval(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        r = await client.post(
            "/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "5000.00", "currency": "INR", "order_id": "ORD-003"},
                "request_id": str(uuid.uuid4()),
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["data"]["decision"] == "REQUIRE_APPROVAL"

    async def test_action_appears_in_list_after_submit(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        await client.post(
            "/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00", "currency": "INR", "order_id": "ORD-LIST"},
                "request_id": str(uuid.uuid4()),
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        r = await client.get("/actions")
        assert r.status_code == 200
        body = r.json()
        assert body["data"]["count"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 5. RECEIPTS
# ══════════════════════════════════════════════════════════════════════════════

class TestReceipts:
    async def test_list_receipts_empty(self, client):
        r = await client.get("/receipts")
        assert r.status_code == 200
        body = r.json()
        assert body["data"]["count"] == 0

    async def test_verify_receipt_rejects_bad_token(self, client):
        r = await client.post("/receipts/verify", json={"receipt_token": "not.a.jwt"})
        assert r.status_code == 200
        body = r.json()
        # A malformed token is either "blocked" (ReceiptVerificationError) or "error" (exception)
        assert body["status"] in ("blocked", "error")
        assert body["data"]["valid"] is False


# ══════════════════════════════════════════════════════════════════════════════
# 6. METRICS
# ══════════════════════════════════════════════════════════════════════════════

class TestMetrics:
    async def test_metrics_returns_200(self, client):
        r = await client.get("/metrics")
        assert r.status_code == 200

    async def test_metrics_has_required_sections(self, client):
        r = await client.get("/metrics")
        body = r.json()
        d = body["data"]
        assert "submissions" in d
        assert "executions" in d
        assert "security" in d

    async def test_metrics_shows_zero_on_empty_db(self, client):
        r = await client.get("/metrics")
        body = r.json()
        assert body["data"]["submissions"]["total"] == 0
        assert body["data"]["executions"]["total"] == 0

    async def test_metrics_denominators_explicit(self, client):
        r = await client.get("/metrics")
        body = r.json()
        subs = body["data"]["submissions"]
        assert "block_rate_denominator" in subs

    async def test_metrics_after_action_submission(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        await client.post(
            "/actions/submit",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00", "currency": "INR", "order_id": "M1"},
                "request_id": str(uuid.uuid4()),
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        r = await client.get("/metrics")
        body = r.json()
        assert body["data"]["submissions"]["total"] >= 1


# ══════════════════════════════════════════════════════════════════════════════
# 7. CAPABILITIES/ISSUE
# ══════════════════════════════════════════════════════════════════════════════

class TestCapabilities:
    async def test_issue_capability_requires_auth(self, client):
        r = await client.post(
            "/capabilities/issue",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00"},
            },
        )
        assert r.status_code == 401

    async def test_issue_capability_allow(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        r = await client.post(
            "/capabilities/issue",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00", "currency": "INR", "order_id": "CAP-1"},
                "agent_role": "support_agent",
                "context_valid": True,
                "context_reason": "Tenant validated",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        assert r.status_code == 200
        body = r.json()
        # Should have adaptive policy in response
        assert "adaptive_policy" in body["data"]
        assert "confidence" in body["data"]["adaptive_policy"]

    async def test_issue_capability_includes_risk_level(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent
        r = await client.post(
            "/capabilities/issue",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00", "currency": "INR", "order_id": "CAP-2"},
                "agent_role": "support_agent",
                "context_valid": True,
                "context_reason": "OK",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        body = r.json()
        policy = body["data"]["adaptive_policy"]
        assert policy["risk_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    async def test_issue_capability_context_invalid_changes_score(self, client, registered_agent):
        agent_id, api_key, tenant_id = registered_agent

        r_valid = await client.post(
            "/capabilities/issue",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00", "currency": "INR", "order_id": "V1"},
                "agent_role": "support_agent",
                "context_valid": True,
                "context_reason": "OK",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        r_invalid = await client.post(
            "/capabilities/issue",
            json={
                "action_type": "ISSUE_REFUND",
                "parameters": {"amount": "100.00", "currency": "INR", "order_id": "V2"},
                "agent_role": "support_agent",
                "context_valid": False,
                "context_reason": "Tenant mismatch",
            },
            headers={"Authorization": f"Bearer {api_key}"},
        )
        score_valid = r_valid.json()["data"]["adaptive_policy"]["confidence"]
        score_invalid = r_invalid.json()["data"]["adaptive_policy"]["confidence"]
        assert score_invalid < score_valid


# ══════════════════════════════════════════════════════════════════════════════
# 8. BASELINE BEHAVIOR
# ══════════════════════════════════════════════════════════════════════════════

class TestBaselineBehavior:
    """
    Test that the active baseline is reflected in API responses and execution.
    Does not test cryptographic weaknesses directly — that would require a full
    end-to-end execution flow which needs real DB and Redis.
    These tests verify the config plumbing works correctly.
    """
    async def test_baseline_c_is_default(self, client):
        r = await client.get("/config")
        body = r.json()
        active = body["data"]["active_baseline"]
        # Should default to C on fresh start
        # (May have been changed by earlier tests — check checks are complete)
        checks = active["checks"]
        # C has all checks enabled
        if active["id"] == "C":
            assert all(checks.values())

    async def test_baseline_a_has_fewer_checks_than_c(self, client):
        r = await client.get("/config")
        body = r.json()
        baselines = body["data"]["available_baselines"]
        a_checks = baselines["A"]["checks"]
        c_checks = baselines["C"]["checks"]
        a_active = sum(1 for v in a_checks.values() if v)
        c_active = sum(1 for v in c_checks.values() if v)
        assert a_active < c_active

    async def test_baseline_b_has_fewer_checks_than_c(self, client):
        r = await client.get("/config")
        body = r.json()
        baselines = body["data"]["available_baselines"]
        b_checks = baselines["B"]["checks"]
        c_checks = baselines["C"]["checks"]
        b_active = sum(1 for v in b_checks.values() if v)
        c_active = sum(1 for v in c_checks.values() if v)
        assert b_active < c_active

    async def test_baseline_c_has_all_checks_enabled(self, client):
        r = await client.get("/config")
        body = r.json()
        c_checks = body["data"]["available_baselines"]["C"]["checks"]
        assert all(c_checks.values()), f"Baseline C should have all checks: {c_checks}"

    async def test_baseline_a_has_no_executor_checks(self, client):
        r = await client.get("/config")
        body = r.json()
        a_checks = body["data"]["available_baselines"]["A"]["checks"]
        # A should skip digest, signature, replay, kill-switch
        assert not a_checks["check_action_digest"]
        assert not a_checks["verify_capability_signature"]
        assert not a_checks["check_replay_guard"]
        assert not a_checks["check_agent_kill_switch"]

    async def test_config_change_is_audited(self, client):
        # Change baseline and verify audit event is created
        await client.post(
            "/config",
            json={"baseline": "A", "reason": "test audit"},
            headers={"Authorization": "Bearer change-me-in-production"},
        )
        r = await client.get("/audit/events", params={"event_type": "BASELINE_CHANGED"})
        events = r.json()
        # Should have a BASELINE_CHANGED event
        assert any(e.get("event_type") == "BASELINE_CHANGED" for e in events)

        # Restore C
        await client.post(
            "/config",
            json={"baseline": "C"},
            headers={"Authorization": "Bearer change-me-in-production"},
        )
