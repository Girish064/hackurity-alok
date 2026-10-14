"""
tests/unit/test_cli.py
Unit tests for the AGSH Terminal CLI (terminal/agsh.py).

Uses Typer's CliRunner with mocked HTTP calls to verify:
  1. CLI help and command discovery
  2. No-color mode
  3. connect command (with and without option)
  4. status command
  5. action submit and actions submit alias
  6. actions list and action list
  7. ledger and ledger list
  8. receipt verify and receipt direct
  9. audit and audit tail
  10. metrics and metrics show
  11. config show and config set
  12. reset --demo
"""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from terminal.agsh import app

runner = CliRunner()


def test_cli_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "AgentShield V3 CLI" in result.output


def test_cli_no_color():
    result = runner.invoke(app, ["--no-color", "--help"])
    assert result.exit_code == 0
    assert "AgentShield V3 CLI" in result.output


def test_connect_command(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = runner.invoke(app, ["connect", "agent-test", "--api-key", "secret-key-12345"])
    assert result.exit_code == 0
    assert "Connected as agent agent-test" in result.output


def test_connect_command_prompts_when_missing_key(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = runner.invoke(app, ["connect", "agent-test"], input="secret-key-12345\n")
    assert result.exit_code == 0
    assert "Connected as agent agent-test" in result.output


def test_connect_command_rejects_short_key(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    result = runner.invoke(app, ["connect", "agent-test", "--api-key", "short"])
    assert result.exit_code == 1
    assert "at least 8 characters" in result.output


@patch("terminal.agsh._get")
def test_status_command(mock_get):
    mock_get.side_effect = [
        {"status": "success", "data": {"overall": "ok", "components": {"database": "ok", "redis": "ok"}}},
        {"status": "success", "data": {"active_baseline": "C", "baseline_name": "Full Enforcement"}},
    ]
    result = runner.invoke(app, ["status"])
    assert result.exit_code == 0
    assert "Baseline: C" in result.output


@patch("terminal.agsh._post")
def test_action_submit_success(mock_post):
    mock_post.return_value = {
        "status": "success",
        "code": "CAPABILITY_ISSUED",
        "message": "Capability issued.",
        "data": {
            "decision": "ALLOW",
            "capability_token": "mock.jwt.token",
            "expires_at": "2026-10-14T20:00:00Z",
            "action_digest": "abcdef0123456789",
        },
    }
    result = runner.invoke(app, ["action", "submit", "--action", "ISSUE_REFUND", "--params", '{"amount":"500.00"}'])
    assert result.exit_code == 0
    assert "Capability issued" in result.output
    assert "mock.jwt.token" in result.output


@patch("terminal.agsh._post")
def test_actions_submit_alias(mock_post):
    mock_post.return_value = {
        "status": "success",
        "code": "CAPABILITY_ISSUED",
        "message": "Capability issued.",
        "data": {"decision": "ALLOW", "capability_token": "token123"},
    }
    result = runner.invoke(app, ["actions", "submit", "--scope", "500", "--params", '{"currency":"INR"}'])
    assert result.exit_code == 0
    assert "Capability issued" in result.output


def test_action_submit_invalid_json():
    result = runner.invoke(app, ["action", "submit", "--params", "not-valid-json"])
    assert result.exit_code == 1
    assert "Invalid JSON in --params" in result.output


@patch("terminal.agsh._get")
def test_action_list_and_actions_list(mock_get):
    mock_get.return_value = {
        "status": "success",
        "data": {
            "actions": [
                {
                    "submitted_at": "2026-10-14T12:00:00Z",
                    "request_id": "00000000-0000-0000-0000-000000000001",
                    "action_type": "ISSUE_REFUND",
                    "policy_decision": "ALLOW",
                    "status": "executed",
                }
            ]
        },
    }
    r1 = runner.invoke(app, ["action", "list"])
    assert r1.exit_code == 0
    assert "ISSUE_REFUND" in r1.output

    r2 = runner.invoke(app, ["actions", "list"])
    assert r2.exit_code == 0
    assert "ISSUE_REFUND" in r2.output


@patch("terminal.agsh._get")
def test_ledger_and_ledger_list(mock_get):
    mock_get.return_value = {
        "status": "success",
        "data": {
            "receipts": [
                {
                    "execution_id": "00000000-0000-0000-0000-000000000002",
                    "agent_id": "00000000-0000-0000-0000-000000000003",
                    "tool_name": "mock_refund_tool",
                    "outcome": "success",
                    "has_receipt": True,
                    "executed_at": "2026-10-14T12:01:00Z",
                }
            ]
        },
    }
    r1 = runner.invoke(app, ["ledger"])
    assert r1.exit_code == 0
    assert "mock_refun" in r1.output

    r2 = runner.invoke(app, ["ledger", "list"])
    assert r2.exit_code == 0
    assert "mock_refun" in r2.output


@patch("terminal.agsh._post")
def test_receipt_verify_command(mock_post, tmp_path):
    token_file = tmp_path / "test_receipt.jwt"
    token_file.write_text("valid.jwt.token")

    mock_post.return_value = {
        "status": "success",
        "code": "RECEIPT_VALID",
        "message": "Receipt signature and claims verified successfully.",
        "data": {
            "valid": True,
            "capability_id": "cap-123",
            "action_digest": "digest-456",
            "executor_id": "exec-789",
            "outcome": "SUCCESS",
            "executed_at": "2026-10-14T12:00:00Z",
        },
    }
    # Test "agsh receipt verify <file>"
    r1 = runner.invoke(app, ["receipt", "verify", str(token_file)])
    assert r1.exit_code == 0
    assert "cap-123" in r1.output

    # Test "agsh receipt <file>"
    r2 = runner.invoke(app, ["receipt", str(token_file)])
    assert r2.exit_code == 0
    assert "cap-123" in r2.output


@patch("terminal.agsh._get")
def test_audit_and_audit_tail(mock_get):
    mock_get.return_value = {
        "status": "success",
        "data": {
            "events": [
                {
                    "sequence_number": 1,
                    "timestamp": "2026-10-14T12:00:00Z",
                    "event_type": "EXECUTION_SUCCESS",
                    "actor_id": "agent-001",
                }
            ]
        },
    }
    r1 = runner.invoke(app, ["audit"])
    assert r1.exit_code == 0
    assert "EXECUTION_SUCCESS" in r1.output

    r2 = runner.invoke(app, ["audit", "tail"])
    assert r2.exit_code == 0
    assert "EXECUTION_SUCCESS" in r2.output


@patch("terminal.agsh._get")
def test_metrics_and_metrics_show(mock_get):
    mock_get.return_value = {
        "status": "success",
        "data": {
            "submissions": {"total": 10, "allowed": 8, "denied": 2, "require_approval": 0, "block_rate": 0.2},
            "executions": {"total": 8, "successful": 8, "failed": 0, "success_rate": 1.0},
            "security": {"unauthorized_executions": 0, "audit_chain_valid": True, "audit_chain_verified_count": 8},
        },
    }
    r1 = runner.invoke(app, ["metrics"])
    assert r1.exit_code == 0
    assert "Security Metrics" in r1.output

    r2 = runner.invoke(app, ["metrics", "show"])
    assert r2.exit_code == 0
    assert "Security Metrics" in r2.output


@patch("terminal.agsh._get")
def test_config_show(mock_get):
    mock_get.return_value = {
        "status": "success",
        "data": {
            "active_baseline": {
                "id": "C",
                "name": "Full AgentShield Enforcement",
                "risk_level": "low",
                "checks": {
                    "policy_evaluation": True,
                    "check_action_digest": True,
                    "verify_capability_signature": True,
                    "check_replay_guard": True,
                    "check_agent_kill_switch": True,
                },
            }
        },
    }
    result = runner.invoke(app, ["config", "show"])
    assert result.exit_code == 0
    assert "Active Baseline: C" in result.output
    assert "Baseline C — Full enforcement active" in result.output


@patch.dict("os.environ", {"ADMIN_SECRET_TOKEN": "test-admin-secret"})
@patch("terminal.agsh._post")
def test_config_set(mock_post):
    mock_post.return_value = {
        "status": "success",
        "code": "CONFIG_UPDATED",
        "message": "Baseline changed from A to C.",
        "data": {"active_baseline": {"id": "C"}},
    }
    result = runner.invoke(app, ["config", "set", "C", "--reason", "Testing switch"])
    assert result.exit_code == 0
    assert "Baseline set to C" in result.output


def test_reset_demo(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    session_file = tmp_path / ".agsh_session.json"
    session_file.write_text(json.dumps({"agent_id": "test"}))

    result = runner.invoke(app, ["reset", "--demo", "--yes"])
    assert result.exit_code == 0
    assert "Demo session context cleared" in result.output
    assert not session_file.exists()
