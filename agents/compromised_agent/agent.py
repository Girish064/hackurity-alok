#!/usr/bin/env python3
"""
agents/compromised_agent/agent.py
Demo script for adversarial scenarios:
  B — Modified action (tampered amount)
  C — Replay (re-using consumed capability)
  E — Revocation (disabled agent attempts action)
  G — Direct bypass (executor without valid token)

Usage:
  python agents/compromised_agent/agent.py --scenario B
  python agents/compromised_agent/agent.py --scenario C
  python agents/compromised_agent/agent.py --scenario E
  python agents/compromised_agent/agent.py --scenario G
"""
from __future__ import annotations

import argparse
import sys
import uuid

import httpx

BASE_URL = "http://localhost:8000"
ADMIN_TOKEN = "change-me-in-production"
TENANT_ID = str(uuid.uuid4())


def register_agent(client, max_refund=2000, permissions=None):
    resp = client.post(
        f"{BASE_URL}/agents",
        json={
            "name": "compromised-agent",
            "tenant_id": TENANT_ID,
            "permissions": permissions or ["ISSUE_REFUND"],
            "max_refund_amount": max_refund,
        },
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    resp.raise_for_status()
    data = resp.json()
    return data["id"], data["api_key"]


def scenario_b(client):
    """Scenario B: Agent tampers the amount after receiving capability."""
    print("\n=== SCENARIO B: Modified Action (Tamper Attack) ===\n")
    agent_id, api_key = register_agent(client)

    original_params = {"amount": "500.00", "currency": "INR", "order_id": "ORD-B01"}
    tampered_params = {"amount": "5000.00", "currency": "INR", "order_id": "ORD-B01"}

    print("[+] Agent requests authorization for ₹500...")
    gw = client.post(
        f"{BASE_URL}/gateway/actions/submit",
        json={"action_type": "ISSUE_REFUND", "parameters": original_params, "request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    gw.raise_for_status()
    cap_token = gw.json()["capability_token"]
    print(f"    Capability issued for digest: {gw.json()['action_digest'][:16]}...")

    print("[!] Agent tampers: attempting to execute ₹5000 with ₹500 capability...")
    exec_resp = client.post(
        f"{BASE_URL}/executor/execute",
        json={"capability_token": cap_token, "action_type": "ISSUE_REFUND", "parameters": tampered_params},
    )
    print(f"    HTTP status: {exec_resp.status_code}")
    print(f"    Response   : {exec_resp.json()}")
    assert exec_resp.status_code in (400, 403), "SECURITY FAILURE: tampered action was accepted!"
    print("[✓] Tampered action correctly rejected by executor.")


def scenario_c(client):
    """Scenario C: Replay attack — reusing a consumed capability."""
    print("\n=== SCENARIO C: Replay Attack ===\n")
    agent_id, api_key = register_agent(client)
    params = {"amount": "500.00", "currency": "INR", "order_id": "ORD-C01"}

    gw = client.post(
        f"{BASE_URL}/gateway/actions/submit",
        json={"action_type": "ISSUE_REFUND", "parameters": params, "request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    gw.raise_for_status()
    cap_token = gw.json()["capability_token"]

    print("[+] First execution (should succeed)...")
    exec1 = client.post(
        f"{BASE_URL}/executor/execute",
        json={"capability_token": cap_token, "action_type": "ISSUE_REFUND", "parameters": params},
    )
    print(f"    HTTP status: {exec1.status_code} → {exec1.json().get('outcome', exec1.json())}")
    assert exec1.status_code == 200, "First execution should succeed."

    print("[!] Replay: submitting same capability again...")
    exec2 = client.post(
        f"{BASE_URL}/executor/execute",
        json={"capability_token": cap_token, "action_type": "ISSUE_REFUND", "parameters": params},
    )
    print(f"    HTTP status: {exec2.status_code}")
    print(f"    Response   : {exec2.json()}")
    assert exec2.status_code == 409, "SECURITY FAILURE: replay was accepted!"
    print("[✓] Replay correctly rejected.")


def scenario_e(client):
    """Scenario E: Revoked agent cannot perform actions."""
    print("\n=== SCENARIO E: Revoked Agent ===\n")
    agent_id, api_key = register_agent(client)

    print(f"[+] Revoking agent {agent_id[:8]}...")
    rv = client.patch(
        f"{BASE_URL}/agents/{agent_id}/revoke",
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    rv.raise_for_status()

    print("[!] Revoked agent attempts to submit action...")
    resp = client.post(
        f"{BASE_URL}/gateway/actions/submit",
        json={"action_type": "ISSUE_REFUND", "parameters": {"amount": "100.00", "currency": "INR", "order_id": "ORD-E01"}, "request_id": str(uuid.uuid4())},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    print(f"    HTTP status: {resp.status_code}")
    print(f"    Response   : {resp.json()}")
    assert resp.status_code in (401, 403), "SECURITY FAILURE: revoked agent was accepted!"
    print("[✓] Revoked agent correctly rejected.")


def scenario_g(client):
    """Scenario G: Direct bypass — executor without a valid capability."""
    print("\n=== SCENARIO G: Direct Bypass Attempt ===\n")
    print("[!] Attempting to call executor directly without authorization...")
    resp = client.post(
        f"{BASE_URL}/executor/execute",
        json={
            "capability_token": "not.a.real.token",
            "action_type": "ISSUE_REFUND",
            "parameters": {"amount": "500.00", "currency": "INR", "order_id": "ORD-G01"},
        },
    )
    print(f"    HTTP status: {resp.status_code}")
    print(f"    Response   : {resp.json()}")
    assert resp.status_code in (400, 403, 422), "SECURITY FAILURE: bypass succeeded!"
    print("[✓] Direct bypass correctly rejected.")


def main():
    parser = argparse.ArgumentParser(description="AgentShield Demo — Compromised Agent")
    parser.add_argument("--scenario", choices=["B", "C", "E", "G"], default="B")
    args = parser.parse_args()

    with httpx.Client(timeout=30.0) as client:
        try:
            client.get(f"{BASE_URL}/health").raise_for_status()
        except Exception as e:
            print(f"[!] Backend not reachable at {BASE_URL}: {e}")
            sys.exit(1)

        scenarios = {"B": scenario_b, "C": scenario_c, "E": scenario_e, "G": scenario_g}
        scenarios[args.scenario](client)


if __name__ == "__main__":
    main()
