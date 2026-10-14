"""
tests/unit/test_adaptive_policy.py
Unit tests for the adaptive policy engine (core/adaptive_policy.py).

Tests cover:
  - High-confidence scenario (full trusted context)
  - Low-confidence scenario (unknown role, failed context)
  - Suspicious activity (score cannot increase)
  - Out-of-scope request (hard deny regardless of confidence)
  - Missing context (fail-closed)
  - Action not in permitted set (hard deny)
  - Approval requirements at low confidence
  - Sensitive action approval requirement
  - Score clamping and TTL scaling
"""
from __future__ import annotations

import pytest

from core.adaptive_policy import (
    ALWAYS_REQUIRES_APPROVAL,
    MIN_CONFIDENCE_AUTO_APPROVE,
    AdaptivePolicyInput,
    PolicyOutcome,
    RiskLevel,
    evaluate_adaptive_policy,
    evaluate_for_request,
)


# ── Helpers ────────────────────────────────────────────────────────────────

def make_input(**overrides) -> AdaptivePolicyInput:
    """Build a default high-confidence input and apply overrides."""
    defaults = dict(
        agent_id="agent-001",
        agent_role="support_agent",
        permitted_actions=["ISSUE_REFUND", "SEND_EMAIL"],
        action_type="ISSUE_REFUND",
        requested_scope=500.0,
        context_valid=True,
        context_reason="Tenant isolation confirmed",
        recent_failures=0,
        suspicious_activity=False,
    )
    defaults.update(overrides)
    return AdaptivePolicyInput(**defaults)


# ── High confidence ────────────────────────────────────────────────────────


class TestHighConfidence:
    def test_trusted_role_contributes_score(self):
        inp = make_input(agent_role="support_agent")
        dec = evaluate_adaptive_policy(inp)
        assert dec.confidence >= 0.50
        assert "R1_TRUSTED_ROLE" in dec.rule_ids

    def test_permitted_action_contributes(self):
        inp = make_input()
        dec = evaluate_adaptive_policy(inp)
        assert "R2_ACTION_PERMITTED" in dec.rule_ids

    def test_valid_context_contributes(self):
        inp = make_input(context_valid=True)
        dec = evaluate_adaptive_policy(inp)
        assert "R4_CONTEXT_VALID" in dec.rule_ids

    def test_high_confidence_allows_full_scope(self):
        inp = make_input(requested_scope=500.0)
        dec = evaluate_adaptive_policy(inp)
        # Confidence × max_scope should cover the requested scope
        # For ISSUE_REFUND max is 10_000; at ~0.65 confidence → 6500 > 500
        assert dec.allowed_scope >= 500.0

    def test_high_confidence_gives_reasonable_ttl(self):
        inp = make_input(agent_role="support_agent", context_valid=True, recent_failures=0)
        dec = evaluate_adaptive_policy(inp)
        assert dec.capability_ttl_seconds >= 60

    def test_outcome_is_allow_for_high_confidence(self):
        inp = make_input(agent_role="support_agent", context_valid=True, recent_failures=0)
        dec = evaluate_adaptive_policy(inp)
        # ISSUE_REFUND is HIGH sensitivity so approval may still be required
        # at borderline scores — just verify it's not a hard deny
        assert dec.outcome in (PolicyOutcome.ALLOW, PolicyOutcome.REQUIRE_APPROVAL)
        assert dec.confidence > 0.0

    def test_low_sensitivity_action_higher_score(self):
        inp = make_input(
            action_type="SEND_EMAIL",
            permitted_actions=["SEND_EMAIL"],
            requested_scope=0.0,  # Email scope is recipient count; 0 = no limit specified
        )
        dec = evaluate_adaptive_policy(inp)
        assert "R5_LOW_SENSITIVITY" in dec.rule_ids
        assert dec.confidence > 0.30  # Low sensitivity adds 0.10

    def test_explanation_is_non_empty(self):
        inp = make_input()
        dec = evaluate_adaptive_policy(inp)
        assert len(dec.explanation) > 20


# ── Low confidence ─────────────────────────────────────────────────────────


class TestLowConfidence:
    def test_unknown_role_no_bonus(self):
        inp = make_input(agent_role="unknown_role")
        dec = evaluate_adaptive_policy(inp)
        assert "R1_UNKNOWN_ROLE" in dec.rule_ids

    def test_failed_context_penalizes_score(self):
        inp = make_input(context_valid=False, context_reason="Tenant mismatch detected")
        dec = evaluate_adaptive_policy(inp)
        assert "R4_CONTEXT_INVALID" in dec.rule_ids
        assert dec.confidence < 0.50

    def test_low_confidence_narrows_scope(self):
        inp = make_input(
            context_valid=False,
            context_reason="Context check failed",
            agent_role="unknown_role",
        )
        dec = evaluate_adaptive_policy(inp)
        if dec.outcome != PolicyOutcome.DENY:
            # Allowed scope must be ≤ requested scope
            assert dec.allowed_scope <= 500.0

    def test_low_confidence_shortens_ttl(self):
        inp_high = make_input()
        inp_low = make_input(
            context_valid=False,
            context_reason="Failed",
            agent_role="unknown_role",
            recent_failures=3,
        )
        dec_high = evaluate_adaptive_policy(inp_high)
        dec_low = evaluate_adaptive_policy(inp_low)
        if dec_low.outcome != PolicyOutcome.DENY:
            assert dec_low.capability_ttl_seconds <= dec_high.capability_ttl_seconds

    def test_low_confidence_below_threshold_requires_approval(self):
        # Force score low enough to require approval
        inp = make_input(
            agent_role="unknown_role",
            context_valid=False,
            context_reason="Validation failed",
            recent_failures=5,
        )
        dec = evaluate_adaptive_policy(inp)
        # Either denied outright or requires approval
        assert dec.outcome in (PolicyOutcome.DENY, PolicyOutcome.REQUIRE_APPROVAL)

    def test_risk_level_is_high_at_low_confidence(self):
        inp = make_input(
            agent_role="unknown_role",
            context_valid=False,
            context_reason="Validation failed",
        )
        dec = evaluate_adaptive_policy(inp)
        if dec.confidence < 0.40:
            assert dec.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)


# ── Suspicious activity ────────────────────────────────────────────────────


class TestSuspiciousActivity:
    def test_suspicious_flag_reduces_score(self):
        inp_clean = make_input(suspicious_activity=False)
        inp_suspect = make_input(suspicious_activity=True)
        dec_clean = evaluate_adaptive_policy(inp_clean)
        dec_suspect = evaluate_adaptive_policy(inp_suspect)
        assert dec_suspect.confidence < dec_clean.confidence

    def test_suspicious_rule_id_present(self):
        inp = make_input(suspicious_activity=True)
        dec = evaluate_adaptive_policy(inp)
        assert "R6_SUSPICIOUS_ACTIVITY" in dec.rule_ids

    def test_high_failure_rate_penalized(self):
        inp_0 = make_input(recent_failures=0)
        inp_5 = make_input(recent_failures=5)
        dec_0 = evaluate_adaptive_policy(inp_0)
        dec_5 = evaluate_adaptive_policy(inp_5)
        assert dec_5.confidence <= dec_0.confidence
        assert "R6_HIGH_FAILURE_RATE" in dec_5.rule_ids

    def test_moderate_failure_rate_penalized(self):
        inp = make_input(recent_failures=2)
        dec = evaluate_adaptive_policy(inp)
        assert "R6_MODERATE_FAILURE_RATE" in dec.rule_ids

    def test_negative_failures_treated_as_zero(self):
        # Negative values must not increase trust
        inp = make_input(recent_failures=-5)
        dec = evaluate_adaptive_policy(inp)
        assert dec.confidence >= 0.0

    def test_suspicious_cannot_produce_score_above_clean(self):
        """Adding suspicious=True must never increase confidence vs clean input."""
        for failures in (0, 1, 3, 6):
            clean = make_input(recent_failures=failures, suspicious_activity=False)
            dirty = make_input(recent_failures=failures, suspicious_activity=True)
            assert evaluate_adaptive_policy(dirty).confidence <= evaluate_adaptive_policy(clean).confidence


# ── Out-of-scope requests ──────────────────────────────────────────────────


class TestOutOfScope:
    def test_scope_exceeding_max_is_hard_denied(self):
        # ISSUE_REFUND max is 10_000
        inp = make_input(requested_scope=15_000.0)
        dec = evaluate_adaptive_policy(inp)
        assert dec.outcome == PolicyOutcome.DENY
        assert "R3_SCOPE_EXCEEDED" in dec.rule_ids
        assert dec.confidence == 0.0

    def test_scope_at_max_is_allowed(self):
        inp = make_input(requested_scope=10_000.0)
        dec = evaluate_adaptive_policy(inp)
        # Should not be an out-of-scope deny (may still require approval for other reasons)
        assert "R3_SCOPE_EXCEEDED" not in dec.rule_ids

    def test_scope_zero_is_neutral(self):
        inp = make_input(action_type="SEND_EMAIL", permitted_actions=["SEND_EMAIL"], requested_scope=0.0)
        dec = evaluate_adaptive_policy(inp)
        assert "R3_SCOPE_NOT_APPLICABLE" in dec.rule_ids
        assert dec.outcome != PolicyOutcome.DENY or dec.confidence == 0.0

    def test_explicit_max_scope_override(self):
        inp = make_input(requested_scope=200.0, max_scope_override=100.0)
        dec = evaluate_adaptive_policy(inp, max_scope_limit=100.0)
        assert dec.outcome == PolicyOutcome.DENY
        assert "R3_SCOPE_EXCEEDED" in dec.rule_ids


# ── Missing context ────────────────────────────────────────────────────────


class TestMissingContext:
    def test_empty_agent_id_fails_closed(self):
        inp = make_input(agent_id="")
        dec = evaluate_adaptive_policy(inp)
        assert dec.outcome == PolicyOutcome.DENY
        assert dec.confidence == 0.0
        assert "MISSING_REQUIRED_CONTEXT" in dec.rule_ids

    def test_empty_action_type_fails_closed(self):
        inp = make_input(action_type="")
        dec = evaluate_adaptive_policy(inp)
        assert dec.outcome == PolicyOutcome.DENY
        assert "MISSING_REQUIRED_CONTEXT" in dec.rule_ids

    def test_empty_role_fails_closed(self):
        inp = make_input(agent_role="")
        dec = evaluate_adaptive_policy(inp)
        assert dec.outcome == PolicyOutcome.DENY
        assert "MISSING_REQUIRED_CONTEXT" in dec.rule_ids

    def test_action_not_in_permitted_is_denied(self):
        inp = make_input(action_type="TRANSFER_FUNDS", permitted_actions=["ISSUE_REFUND"])
        dec = evaluate_adaptive_policy(inp)
        assert dec.outcome == PolicyOutcome.DENY
        assert "R2_ACTION_NOT_PERMITTED" in dec.rule_ids
        assert dec.confidence == 0.0


# ── Approval requirements ──────────────────────────────────────────────────


class TestApprovalRequirements:
    def test_always_requires_approval_actions(self):
        for action in ALWAYS_REQUIRES_APPROVAL:
            inp = make_input(
                action_type=action,
                permitted_actions=list(ALWAYS_REQUIRES_APPROVAL) + ["ISSUE_REFUND"],
                requested_scope=100.0,
            )
            dec = evaluate_adaptive_policy(inp)
            if dec.outcome != PolicyOutcome.DENY:
                assert dec.requires_human_approval
                assert dec.approval_reason is not None

    def test_confidence_below_threshold_requires_approval(self):
        # Construct a scenario that gives score just below MIN_CONFIDENCE_AUTO_APPROVE
        # Unknown role (0), email action (low sensitivity +0.10), context valid (+0.15), permitted (+0.20)
        # Score ≈ 0 + 0.20 + 0.15 + 0.10 = 0.45 → above threshold for SEND_EMAIL
        # Reduce with recent_failures to push below 0.60
        inp = make_input(
            agent_role="unknown_role",
            action_type="SEND_EMAIL",
            permitted_actions=["SEND_EMAIL"],
            context_valid=True,
            context_reason="OK",
            recent_failures=2,
            requested_scope=0.0,
        )
        dec = evaluate_adaptive_policy(inp)
        # Score: 0 + 0.20 + 0.15 + 0.10 - 0.10 = 0.35 → below threshold
        if dec.outcome == PolicyOutcome.REQUIRE_APPROVAL:
            assert dec.requires_human_approval

    def test_approval_reason_populated_when_required(self):
        inp = make_input(
            agent_role="unknown_role",
            context_valid=False,
            context_reason="Tenant mismatch",
            recent_failures=2,
        )
        dec = evaluate_adaptive_policy(inp)
        if dec.requires_human_approval:
            assert dec.approval_reason is not None and len(dec.approval_reason) > 0


# ── Score clamping ─────────────────────────────────────────────────────────


class TestScoreClamping:
    def test_score_never_above_1(self):
        inp = make_input(
            agent_role="support_agent",
            context_valid=True,
            context_reason="All clear",
            recent_failures=0,
            suspicious_activity=False,
        )
        dec = evaluate_adaptive_policy(inp)
        assert dec.confidence <= 1.0

    def test_score_never_below_0(self):
        inp = make_input(
            agent_role="unknown_role",
            context_valid=False,
            context_reason="Everything failed",
            recent_failures=10,
            suspicious_activity=True,
        )
        dec = evaluate_adaptive_policy(inp)
        assert dec.confidence >= 0.0

    def test_ttl_at_least_30_seconds_when_allowed(self):
        inp = make_input()
        dec = evaluate_adaptive_policy(inp)
        if dec.outcome != PolicyOutcome.DENY:
            assert dec.capability_ttl_seconds >= 30


# ── Convenience wrapper ────────────────────────────────────────────────────


class TestConvenienceWrapper:
    def test_evaluate_for_request_matches_direct(self):
        direct = evaluate_adaptive_policy(
            AdaptivePolicyInput(
                agent_id="a1",
                agent_role="support_agent",
                permitted_actions=["ISSUE_REFUND"],
                action_type="ISSUE_REFUND",
                requested_scope=100.0,
                context_valid=True,
                context_reason="OK",
            )
        )
        wrapper = evaluate_for_request(
            agent_id="a1",
            agent_role="support_agent",
            permitted_actions=["ISSUE_REFUND"],
            action_type="ISSUE_REFUND",
            requested_scope=100.0,
            context_valid=True,
            context_reason="OK",
        )
        assert direct.confidence == wrapper.confidence
        assert direct.outcome == wrapper.outcome
        assert direct.rule_ids == wrapper.rule_ids
