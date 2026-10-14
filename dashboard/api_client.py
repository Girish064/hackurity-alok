"""
dashboard/api_client.py
Thin HTTP client for the AgentShield backend API.

All dashboard data comes from the backend — no local DB access, no fabrication.
"""
from __future__ import annotations

import os
from typing import Any, Optional

import httpx

_BASE_URL = os.environ.get("AGENTSHIELD_API_URL", "http://localhost:8000")
_TIMEOUT = 8.0  # seconds


def _client() -> httpx.Client:
    return httpx.Client(base_url=_BASE_URL, timeout=_TIMEOUT)


def get(path: str, params: Optional[dict] = None) -> dict[str, Any]:
    try:
        with _client() as c:
            r = c.get(path, params=params)
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        return {"status": "error", "code": "API_UNREACHABLE", "message": f"Cannot connect to {_BASE_URL}", "data": {}}
    except httpx.HTTPStatusError as exc:
        return {"status": "error", "code": f"HTTP_{exc.response.status_code}", "message": str(exc), "data": {}}
    except Exception as exc:
        return {"status": "error", "code": "CLIENT_ERROR", "message": str(exc), "data": {}}


def post(path: str, json: dict, headers: Optional[dict] = None) -> dict[str, Any]:
    try:
        with _client() as c:
            r = c.post(path, json=json, headers=headers or {})
            r.raise_for_status()
            return r.json()
    except httpx.ConnectError:
        return {"status": "error", "code": "API_UNREACHABLE", "message": f"Cannot connect to {_BASE_URL}", "data": {}}
    except httpx.HTTPStatusError as exc:
        try:
            body = exc.response.json()
        except Exception:
            body = {"message": str(exc)}
        return {"status": "error", "code": f"HTTP_{exc.response.status_code}", "message": body.get("message", str(exc)), "data": body}
    except Exception as exc:
        return {"status": "error", "code": "CLIENT_ERROR", "message": str(exc), "data": {}}


# ── Typed helpers ──────────────────────────────────────────────────────────

def health() -> dict:
    return get("/health")

def system_status() -> dict:
    return get("/system/status")

def get_config() -> dict:
    return get("/config")

def get_metrics() -> dict:
    return get("/metrics")

def list_actions(limit: int = 50) -> dict:
    return get("/actions", params={"limit": limit})

def get_action(request_id: str) -> dict:
    return get(f"/actions/{request_id}")

def list_receipts(limit: int = 50) -> dict:
    return get("/receipts", params={"limit": limit})

def list_audit(limit: int = 100) -> dict:
    return get("/audit/events", params={"limit": limit})

def verify_receipt(token: str) -> dict:
    return post("/receipts/verify", json={"receipt_token": token})

def verify_audit_chain(admin_token: str) -> dict:
    return post("/audit/verify-chain", json={}, headers={"Authorization": f"Bearer {admin_token}"})

def set_config(baseline: str, admin_token: str, reason: str = "") -> dict:
    return post(
        "/config",
        json={"baseline": baseline, "reason": reason},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
