"""Tests for Component A — Canonical Action Representation (`canonicalization.py`)."""

from __future__ import annotations

import copy
from decimal import Decimal

import pytest

from app.security.canonicalization import (
    CanonicalizationError,
    DuplicateKeyError,
    SchemaValidationError,
    canonicalize_action,
    validate_and_normalize_action,
)


@pytest.fixture
def valid_action() -> dict:
    return {
        "schema_version": 1,
        "tenant_id": "tenant-demo",
        "principal_id": "agent-support-01",
        "tool": "issue_refund",
        "resource": "orders/ORDER-123",
        "arguments": {
            "order_id": "ORDER-123",
            "amount_minor": 50000,
            "currency": "INR",
            "metadata": {"reason": "damaged_item", "priority": 1},
        },
        "environment": "demo",
        "policy_version": 3,
        "intent_id": "intent-demo-001",
    }


def test_canonicalize_valid_action_deterministic_bytes(valid_action: dict) -> None:
    """Identical actions with different key ordering produce identical canonical UTF-8 bytes."""
    reordered = {
        "intent_id": "intent-demo-001",
        "policy_version": 3,
        "environment": "demo",
        "arguments": {
            "metadata": {"priority": 1, "reason": "damaged_item"},
            "currency": "INR",
            "amount_minor": 50000,
            "order_id": "ORDER-123",
        },
        "resource": "orders/ORDER-123",
        "tool": "issue_refund",
        "principal_id": "agent-support-01",
        "tenant_id": "tenant-demo",
        "schema_version": "1",  # string "1" normalizes to int 1
    }
    bytes_a = canonicalize_action(valid_action)
    bytes_b = canonicalize_action(reordered)
    assert bytes_a == bytes_b
    assert b" " not in bytes_a  # No extraneous whitespace


def test_reject_duplicate_json_keys_top_level_and_nested() -> None:
    """Duplicate JSON keys at top-level or nested inside arguments must be rejected."""
    raw_top_dup = """
    {
      "schema_version": 1,
      "tenant_id": "tenant-001",
      "tenant_id": "tenant-002",
      "principal_id": "agent-007",
      "tool": "refund",
      "resource": "order-123",
      "arguments": {"amount_minor": 50000},
      "environment": "demo",
      "policy_version": 1,
      "intent_id": "intent-001"
    }
    """
    with pytest.raises(DuplicateKeyError) as exc_info:
        canonicalize_action(raw_top_dup)
    assert exc_info.value.error_code == "DUPLICATE_JSON_KEY"

    raw_nested_dup = """
    {
      "schema_version": 1,
      "tenant_id": "tenant-001",
      "principal_id": "agent-007",
      "tool": "refund",
      "resource": "order-123",
      "arguments": {"amount_minor": 50000, "amount_minor": 500000},
      "environment": "demo",
      "policy_version": 1,
      "intent_id": "intent-001"
    }
    """
    with pytest.raises(DuplicateKeyError) as exc_info2:
        canonicalize_action(raw_nested_dup)
    assert exc_info2.value.error_code == "DUPLICATE_JSON_KEY"


def test_reject_floating_point_and_ambiguous_numbers(valid_action: dict) -> None:
    """Floats, Decimals, scientific notation, -0, and leading zeros must be rejected."""
    act_float = copy.deepcopy(valid_action)
    act_float["arguments"]["amount_minor"] = 500.00
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_action(act_float)
    assert exc_info.value.error_code == "FLOAT_NOT_ALLOWED"

    act_decimal = copy.deepcopy(valid_action)
    act_decimal["arguments"]["amount_minor"] = Decimal("50000")
    with pytest.raises(CanonicalizationError) as exc_info2:
        canonicalize_action(act_decimal)
    assert exc_info2.value.error_code == "FLOAT_NOT_ALLOWED"

    raw_exp_json = """
    {
      "schema_version": 1,
      "tenant_id": "tenant-001",
      "principal_id": "agent-007",
      "tool": "refund",
      "resource": "order-123",
      "arguments": {"amount_minor": 5e4},
      "environment": "demo",
      "policy_version": 1,
      "intent_id": "intent-001"
    }
    """
    with pytest.raises(CanonicalizationError) as exc_info3:
        canonicalize_action(raw_exp_json)
    assert exc_info3.value.error_code == "FLOAT_NOT_ALLOWED"

    raw_neg_zero = """
    {
      "schema_version": 1,
      "tenant_id": "tenant-001",
      "principal_id": "agent-007",
      "tool": "refund",
      "resource": "order-123",
      "arguments": {"amount_minor": 50000, "offset": -0},
      "environment": "demo",
      "policy_version": 1,
      "intent_id": "intent-001"
    }
    """
    with pytest.raises(CanonicalizationError) as exc_info4:
        canonicalize_action(raw_neg_zero)
    assert exc_info4.value.error_code == "AMBIGUOUS_NUMBER"


def test_reject_explicit_null_and_missing_fields(valid_action: dict) -> None:
    """Explicit nulls and missing required fields must be rejected."""
    act_null_arg = copy.deepcopy(valid_action)
    act_null_arg["arguments"]["optional_note"] = None
    with pytest.raises(CanonicalizationError) as exc_info:
        canonicalize_action(act_null_arg)
    assert exc_info.value.error_code == "EXPLICIT_NULL_NOT_ALLOWED"

    act_missing = copy.deepcopy(valid_action)
    del act_missing["tenant_id"]
    with pytest.raises(SchemaValidationError) as exc_info2:
        canonicalize_action(act_missing)
    assert exc_info2.value.error_code == "MISSING_REQUIRED_FIELD"


def test_reject_unknown_extra_fields(valid_action: dict) -> None:
    """Unsupported top-level fields must be rejected."""
    act_extra = copy.deepcopy(valid_action)
    act_extra["bypass_policy"] = True
    with pytest.raises(SchemaValidationError) as exc_info:
        canonicalize_action(act_extra)
    assert exc_info.value.error_code == "UNKNOWN_FIELD"


def test_unicode_nfc_normalization(valid_action: dict) -> None:
    """Equivalent Unicode strings in NFD and NFC forms normalize to identical canonical bytes."""
    act_nfc = copy.deepcopy(valid_action)
    act_nfd = copy.deepcopy(valid_action)
    # "café" in NFC (\u00e9) vs NFD (e + \u0301)
    act_nfc["arguments"]["merchant_name"] = "caf\u00e9"
    act_nfd["arguments"]["merchant_name"] = "cafe\u0301"
    assert canonicalize_action(act_nfc) == canonicalize_action(act_nfd)


def test_reject_boolean_masquerading_as_integer(valid_action: dict) -> None:
    """In Python isinstance(True, int) is True; schema_version, policy_version, and amount_minor must reject booleans."""
    act_bool_ver = copy.deepcopy(valid_action)
    act_bool_ver["schema_version"] = True
    with pytest.raises(SchemaValidationError):
        validate_and_normalize_action(act_bool_ver)

    act_bool_amt = copy.deepcopy(valid_action)
    act_bool_amt["arguments"]["amount_minor"] = True
    with pytest.raises(SchemaValidationError):
        validate_and_normalize_action(act_bool_amt)
