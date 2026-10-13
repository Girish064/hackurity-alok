#!/usr/bin/env python3
"""
agents/legitimate_agent/agent.py
Demo script for Scenario A (legitimate authorized refund) and
Scenario D (action requiring human approval).

Usage:
  python agents/legitimate_agent/agent.py --scenario A
  python agents/legitimate_agent/agent.py --scenario D
"""
from __future__ import annotations

import argparse
import sys
import time
import uuid

import httpx

BASE_URL = "http://localhost:8000"
ADMIN_TOKEN = "change-me-in-production"  # match ADMIN_SECRET_TOKEN in .env
TENANT_ID = str(uuid.uuid4())


def register_agent(client: httpx.Client, max_refund: float, permissions: list) -> tuple[str, str]:
    print(f"[+] Registering agent with max_refund={max_refund}...")
    resp = client.post(
        f"{BASE_URL}/agents",
        json={
            "name": "support-agent-01",
            "tenant_id": TENANT_ID,
            "permissions": permissions,
            "max_refund_amount": max_refund,
        },
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    resp.raise_for_status()
    data = resp.json()
    print(f"    Agent ID : {data['id']}")
    print(f"    API Key  : {data['api_key'][:8]}... (truncated)")
    return data["id"], data["api_key"]


def submit_action(client: httpx.Client, api_key: str, params: dict, request_id: str) -> dict:
    print(f"[+] Submitting action to gateway (request_id={request_id[:8]}...)...")
    resp = client.post(
        f"{BASE_URL}/gateway/actions/submit",
        json={"action_type": "ISSUE_REFUND", "parameters": params, "request_id": request_id},
        headers={"Authorization": f"Bearer {api_key}"},
    )
    resp.raise_for_status()
    return resp.json()


def execute_action(client: httpx.Client, capability_token: str, params: dict) -> dict:
    print("[+] Presenting capability to executor...")
    resp = client.post(
        f"{BASE_URL}/executor/execute",
        json={
            "capability_token": capability_token,
            "action_type": "ISSUE_REFUND",
            "parameters": params,
        },
    )
    resp.raise_for_status()
    return resp.json()


def scenario_a(client: httpx.Client) -> None:
    """Scenario A: Authorized ₹500 refund — full happy path."""
    print("\n=== SCENARIO A: Legitimate Authorized Refund ===\n")
    agent_id, api_key = register_agent(client, max_refund=2000, permissions=["ISSUE_REFUND"])

    params = {"amount": "500.00", "currency": "INR", "order_id": "ORD-001"}
    request_id = str(uuid.uuid4())

    gw = submit_action(client, api_key, params, request_id)
    print(f"    Gateway decision : {gw['decision']}")
    print(f"    Action digest    : {gw['action_digest'][:16]}...")
    print(f"    Expires at       : {gw['expires_at']}")

    result = execute_action(client, gw["capability_token"], params)
    print(f"\n[✓] Execution result:")
    print(f"    Execution ID : {result['execution_id']}")
    print(f"    Outcome      : {result['outcome']}")
    print(f"    Refund ID    : {result['outcome_data'].get('refund_id')}")
    print(f"    Receipt      : {result['receipt_token'][:32]}...")


def scenario_d(client: httpx.Client) -> None:
    """Scenario D: Refund requiring human approval."""
    print("\n=== SCENARIO D: Action Requiring Human Approval ===\n")
    # Amount above ₹1000 requires approval
    agent_id, api_key = register_agent(client, max_refund=5000, permissions=["ISSUE_REFUND"])

    params = {"amount": "1500.00", "currency": "INR", "order_id": "ORD-002"}
    request_id = str(uuid.uuid4())

    gw = submit_action(client, api_key, params, request_id)
    print(f"    Gateway decision : {gw['decision']}")
    print(f"    Approval ID      : {gw.get('approval_id')}")

    approval_id = gw.get("approval_id")
    if not approval_id:
        print("[!] No approval ID returned — check gateway response.")
        return

    print(f"\n[~] Simulating admin approval of {approval_id[:8]}...")
    approve_resp = client.post(
        f"{BASE_URL}/approvals/{approval_id}/decide",
        json={"decision": "approved", "decided_by": "admin@example.com"},
        headers={"Authorization": f"Bearer {ADMIN_TOKEN}"},
    )
    approve_resp.raise_for_status()
    print(f"    Approval status  : {approve_resp.json()['status']}")

    # Re-submit same request_id to get capability
    print("\n[+] Re-submitting to gateway after approval...")
    gw2 = submit_action(client, api_key, params, request_id)
    print(f"    Gateway decision : {gw2['decision']}")

    if gw2.get("capability_token"):
        result = execute_action(client, gw2["capability_token"], params)
        print(f"\n[✓] Execution result:")
        print(f"    Outcome          : {result['outcome']}")
        print(f"    Refund ID        : {result['outcome_data'].get('refund_id')}")


def main():
    parser = argparse.ArgumentParser(description="AgentShield Demo — Legitimate Agent")
    parser.add_argument("--scenario", choices=["A", "D"], default="A")
    args = parser.parse_args()

    with httpx.Client(timeout=30.0) as client:
        # Check server is up
        try:
            client.get(f"{BASE_URL}/health").raise_for_status()
        except Exception as e:
            print(f"[!] Backend not reachable at {BASE_URL}: {e}")
            sys.exit(1)

        if args.scenario == "A":
            scenario_a(client)
        elif args.scenario == "D":
            scenario_d(client)


if __name__ == "__main__":
    main()
