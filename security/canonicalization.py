"""Component A — Canonical Action Representation for AgentShield V2.

Provides deterministic validation, normalization, and canonical byte serialization
for all security-sensitive actions across the gateway, approval service, protected
executor, and audit verifier.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from decimal import Decimal
from typing import Any, Mapping, Union

SUPPORTED_SCHEMA_VERSIONS = {1}
MAX_SAFE_INT = (1 << 53) - 1
MIN_SAFE_INT = -((1 << 53) - 1)
MAX_IDENTIFIER_LEN = 256
MAX_NESTING_DEPTH = 16

REQUIRED_ACTION_FIELDS = frozenset(
    {
        "schema_version",
        "tenant_id",
        "principal_id",
        "tool",
        "resource",
        "arguments",
        "environment",
        "policy_version",
        "intent_id",
    }
)

# Regex to strip JSON string literals before checking raw numeric tokens
_JSON_STRING_RE = re.compile(r'"(?:\\.|[^"\\])*"')
# Detect negative zero (-0) or leading-zero numbers (e.g. 01) outside strings
_AMBIGUOUS_JSON_NUM_RE = re.compile(r"(?:^|[,:\[\{\s])(-0(?![.\d])|0\d+)")
# Detect numeric strings representing floats/currency in amount fields
_FLOAT_STRING_RE = re.compile(r"^[+-]?\d+(\.\d+)?([eE][+-]?\d+)?$")

from .exceptions import AgentShieldSecurityError


class CanonicalizationError(AgentShieldSecurityError, ValueError):
    """Raised when an action or protocol object fails canonicalization or validation."""

    def __init__(self, message: str, error_code: str = "CANONICALIZATION_ERROR") -> None:
        super().__init__(message)
        self.error_code = error_code


class DuplicateKeyError(CanonicalizationError):
    """Raised when a JSON object contains duplicate keys before or after NFC normalization."""

    def __init__(self, key: str) -> None:
        super().__init__(
            f"Duplicate JSON object key detected: {key!r}",
            error_code="DUPLICATE_JSON_KEY",
        )
        self.key = key


class SchemaValidationError(CanonicalizationError):
    """Raised when an action violates the canonical AgentShield action schema."""

    def __init__(self, message: str, error_code: str = "SCHEMA_VALIDATION_ERROR") -> None:
        super().__init__(message, error_code=error_code)


@dataclass(frozen=True)
class CanonicalAction:
    """Validated, immutable representation of an AgentShield V2 action envelope."""

    schema_version: int
    tenant_id: str
    principal_id: str
    tool: str
    resource: str
    arguments: dict[str, Any]
    environment: str
    policy_version: Union[int, str]
    intent_id: str

    def to_dict(self) -> dict[str, Any]:
        """Return a canonical dictionary representation."""
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "principal_id": self.principal_id,
            "tool": self.tool,
            "resource": self.resource,
            "arguments": self.arguments,
            "environment": self.environment,
            "policy_version": self.policy_version,
            "intent_id": self.intent_id,
        }

    def canonical_bytes(self) -> bytes:
        """Return deterministic UTF-8 canonical JSON bytes."""
        return canonicalize_json_object(self.to_dict())


def _reject_float(num_str: str) -> Any:
    raise CanonicalizationError(
        f"Floating-point or exponential number {num_str!r} is prohibited in canonical actions; "
        "use integer minor units (e.g., paise).",
        error_code="FLOAT_NOT_ALLOWED",
    )


def _reject_constant(const_str: str) -> Any:
    raise CanonicalizationError(
        f"Invalid numeric constant {const_str!r} (NaN/Infinity) is prohibited.",
        error_code="INVALID_NUMERIC_CONSTANT",
    )


def _strict_object_pairs_hook(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for raw_key, value in pairs:
        if not isinstance(raw_key, str):
            raise CanonicalizationError(
                f"Object key must be a string, got {type(raw_key).__name__}.",
                error_code="INVALID_KEY_TYPE",
            )
        norm_key = unicodedata.normalize("NFC", raw_key)
        if raw_key in result or norm_key in result:
            raise DuplicateKeyError(norm_key)
        result[norm_key] = value
    return result


def parse_strict_json(raw_json: Union[str, bytes, bytearray]) -> dict[str, Any]:
    """Parse raw JSON strictly, rejecting duplicate keys, floats, -0, and NaN/Infinity."""
    if isinstance(raw_json, (bytes, bytearray)):
        try:
            text = bytes(raw_json).decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise CanonicalizationError(
                f"Action JSON must be valid UTF-8: {exc}",
                error_code="INVALID_UTF8",
            ) from exc
    elif isinstance(raw_json, str):
        text = raw_json
    else:
        raise CanonicalizationError(
            f"Expected JSON string or bytes, got {type(raw_json).__name__}",
            error_code="INVALID_INPUT_TYPE",
        )

    # Check for negative zero (-0) outside of string literals
    stripped = _JSON_STRING_RE.sub('""', text)
    ambiguous_match = _AMBIGUOUS_JSON_NUM_RE.search(stripped)
    if ambiguous_match:
        token = ambiguous_match.group(1)
        raise CanonicalizationError(
            f"Ambiguous numeric representation {token!r} is prohibited.",
            error_code="AMBIGUOUS_NUMBER",
        )

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_strict_object_pairs_hook,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalizationError:
        raise
    except json.JSONDecodeError as exc:
        raise CanonicalizationError(
            f"Invalid JSON input: {exc}",
            error_code="INVALID_JSON",
        ) from exc

    if not isinstance(parsed, dict):
        raise SchemaValidationError(
            "Top-level action payload must be a JSON object.",
            error_code="INVALID_TOP_LEVEL_TYPE",
        )
    return parsed


def _validate_identifier(value: Any, field_name: str) -> str:
    """Validate and NFC-normalize a security-critical identifier string."""
    if not isinstance(value, str):
        raise SchemaValidationError(
            f"Field {field_name!r} must be a string, got {type(value).__name__}.",
            error_code="INVALID_FIELD_TYPE",
        )
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or not normalized.strip():
        raise SchemaValidationError(
            f"Field {field_name!r} must not be empty.",
            error_code="EMPTY_IDENTIFIER",
        )
    if normalized != normalized.strip():
        raise SchemaValidationError(
            f"Field {field_name!r} must not contain leading or trailing whitespace.",
            error_code="AMBIGUOUS_WHITESPACE",
        )
    if len(normalized) > MAX_IDENTIFIER_LEN:
        raise SchemaValidationError(
            f"Field {field_name!r} exceeds maximum length of {MAX_IDENTIFIER_LEN}.",
            error_code="IDENTIFIER_TOO_LONG",
        )
    for ch in normalized:
        code = ord(ch)
        if code < 0x20 or code == 0x7F:
            raise SchemaValidationError(
                f"Field {field_name!r} contains prohibited control character U+{code:04X}.",
                error_code="CONTROL_CHAR_PROHIBITED",
            )
    return normalized


def _validate_schema_version(value: Any) -> int:
    """Validate schema_version and normalize to canonical integer 1."""
    if isinstance(value, bool):
        raise SchemaValidationError(
            "Field 'schema_version' must be integer 1 or string '1', not boolean.",
            error_code="INVALID_SCHEMA_VERSION",
        )
    if isinstance(value, int):
        version = value
    elif isinstance(value, str):
        norm = unicodedata.normalize("NFC", value)
        if norm != norm.strip() or not norm.isdigit():
            raise SchemaValidationError(
                f"Unsupported or malformed schema_version: {value!r}.",
                error_code="INVALID_SCHEMA_VERSION",
            )
        version = int(norm)
    else:
        raise SchemaValidationError(
            f"Field 'schema_version' must be int or str, got {type(value).__name__}.",
            error_code="INVALID_SCHEMA_VERSION",
        )

    if version not in SUPPORTED_SCHEMA_VERSIONS:
        raise SchemaValidationError(
            f"Unsupported schema_version {version!r}; supported versions: {sorted(SUPPORTED_SCHEMA_VERSIONS)}.",
            error_code="UNSUPPORTED_SCHEMA_VERSION",
        )
    return version


def _validate_policy_version(value: Any) -> Union[int, str]:
    """Validate policy_version (positive int or non-empty identifier str)."""
    if isinstance(value, bool):
        raise SchemaValidationError(
            "Field 'policy_version' cannot be a boolean.",
            error_code="INVALID_FIELD_TYPE",
        )
    if isinstance(value, int):
        if value < 1 or value > MAX_SAFE_INT:
            raise SchemaValidationError(
                f"Integer 'policy_version' must be between 1 and {MAX_SAFE_INT}, got {value}.",
                error_code="INVALID_POLICY_VERSION",
            )
        return value
    if isinstance(value, str):
        return _validate_identifier(value, "policy_version")
    raise SchemaValidationError(
        f"Field 'policy_version' must be positive int or non-empty str, got {type(value).__name__}.",
        error_code="INVALID_FIELD_TYPE",
    )


def _normalize_argument_value(value: Any, path: str, depth: int) -> Any:
    """Recursively validate and normalize values inside action arguments."""
    if depth > MAX_NESTING_DEPTH:
        raise CanonicalizationError(
            f"Maximum nesting depth ({MAX_NESTING_DEPTH}) exceeded at {path}.",
            error_code="MAX_DEPTH_EXCEEDED",
        )

    if value is None:
        raise CanonicalizationError(
            f"Explicit null value at {path!r} is prohibited in canonical actions; "
            "omit optional fields instead.",
            error_code="EXPLICIT_NULL_NOT_ALLOWED",
        )

    if isinstance(value, bool):
        return value

    if isinstance(value, int):
        if value < MIN_SAFE_INT or value > MAX_SAFE_INT:
            raise CanonicalizationError(
                f"Integer at {path!r} ({value}) is outside safe integer bounds "
                f"[{MIN_SAFE_INT}, {MAX_SAFE_INT}].",
                error_code="INTEGER_OUT_OF_RANGE",
            )
        return value

    if isinstance(value, (float, Decimal, complex)):
        raise CanonicalizationError(
            f"Floating-point or decimal value at {path!r} ({value!r}) is prohibited; "
            "use exact integer minor units (e.g., paise).",
            error_code="FLOAT_NOT_ALLOWED",
        )

    if isinstance(value, str):
        norm_str = unicodedata.normalize("NFC", value)
        if "\x00" in norm_str:
            raise CanonicalizationError(
                f"String at {path!r} contains prohibited NUL byte.",
                error_code="NUL_BYTE_PROHIBITED",
            )
        return norm_str

    if isinstance(value, (list, tuple)):
        return [
            _normalize_argument_value(item, f"{path}[{idx}]", depth + 1)
            for idx, item in enumerate(value)
        ]

    if isinstance(value, Mapping):
        normalized_dict: dict[str, Any] = {}
        for raw_key, sub_val in value.items():
            if not isinstance(raw_key, str):
                raise CanonicalizationError(
                    f"Argument key at {path!r} must be a string, got {type(raw_key).__name__}.",
                    error_code="INVALID_KEY_TYPE",
                )
            norm_key = unicodedata.normalize("NFC", raw_key)
            if not norm_key or norm_key != norm_key.strip():
                raise CanonicalizationError(
                    f"Argument key {raw_key!r} at {path!r} must be non-empty without surrounding whitespace.",
                    error_code="INVALID_ARGUMENT_KEY",
                )
            for ch in norm_key:
                if ord(ch) < 0x20 or ord(ch) == 0x7F:
                    raise CanonicalizationError(
                        f"Argument key {norm_key!r} contains control characters.",
                        error_code="CONTROL_CHAR_PROHIBITED",
                    )
            if norm_key in normalized_dict:
                raise DuplicateKeyError(norm_key)

            sub_path = f"{path}.{norm_key}"
            norm_sub_val = _normalize_argument_value(sub_val, sub_path, depth + 1)

            # Enforce strict money rules on amount fields
            if norm_key == "amount_minor" or norm_key.endswith("_amount_minor"):
                if isinstance(norm_sub_val, bool) or not isinstance(norm_sub_val, int):
                    raise SchemaValidationError(
                        f"Money field {sub_path!r} must be an integer in minor units (paise).",
                        error_code="INVALID_AMOUNT_TYPE",
                    )
                if norm_sub_val <= 0:
                    raise SchemaValidationError(
                        f"Money field {sub_path!r} must be a positive integer (> 0), got {norm_sub_val}.",
                        error_code="INVALID_AMOUNT_VALUE",
                    )
            elif norm_key in {"amount", "amount_minor"} and isinstance(norm_sub_val, str):
                if _FLOAT_STRING_RE.match(norm_sub_val.strip()):
                    raise CanonicalizationError(
                        f"Ambiguous string numeric representation {norm_sub_val!r} at {sub_path!r}; "
                        "use integer 'amount_minor' in paise.",
                        error_code="AMBIGUOUS_NUMERIC_STRING",
                    )

            normalized_dict[norm_key] = norm_sub_val
        return normalized_dict

    raise CanonicalizationError(
        f"Unsupported value type {type(value).__name__!r} at {path!r}.",
        error_code="INVALID_FIELD_TYPE",
    )


def coerce_to_mapping(obj: Any) -> Mapping[str, Any]:
    """Coerce a Mapping, Pydantic BaseModel, dataclass, or object with to_dict() into a Mapping."""
    if isinstance(obj, Mapping):
        return obj
    if hasattr(obj, "to_dict") and callable(obj.to_dict):
        res = obj.to_dict()
        if isinstance(res, Mapping):
            return res
    if hasattr(obj, "model_dump") and callable(obj.model_dump):
        res = obj.model_dump()
        if isinstance(res, Mapping):
            return res
    if hasattr(obj, "dict") and callable(obj.dict):
        res = obj.dict()
        if isinstance(res, Mapping):
            return res
    raise SchemaValidationError(
        f"Expected a Mapping, Pydantic model, or JSON str/bytes; got {type(obj).__name__}.",
        error_code="INVALID_INPUT_TYPE",
    )


def validate_and_normalize_action(
    action: Any,
) -> CanonicalAction:
    """Validate an action against the AgentShield V2 schema and return a CanonicalAction."""
    if isinstance(action, CanonicalAction):
        raw_dict: Mapping[str, Any] = action.to_dict()
    elif isinstance(action, (str, bytes, bytearray)):
        raw_dict = parse_strict_json(action)
    else:
        coerced = coerce_to_mapping(action)
        # Check for NFC key collisions in Python mapping input
        checked: dict[str, Any] = {}
        for k, v in coerced.items():
            if not isinstance(k, str):
                raise SchemaValidationError(
                    f"Action field key must be a string, got {type(k).__name__}.",
                    error_code="INVALID_KEY_TYPE",
                )
            nk = unicodedata.normalize("NFC", k)
            if nk in checked:
                raise DuplicateKeyError(nk)
            checked[nk] = v
        raw_dict = checked

    present_keys = set(raw_dict.keys())
    missing_keys = REQUIRED_ACTION_FIELDS - present_keys
    if missing_keys:
        raise SchemaValidationError(
            f"Action is missing required fields: {sorted(missing_keys)}.",
            error_code="MISSING_REQUIRED_FIELD",
        )

    extra_keys = present_keys - REQUIRED_ACTION_FIELDS
    if extra_keys:
        raise SchemaValidationError(
            f"Action contains unsupported unknown fields: {sorted(extra_keys)}.",
            error_code="UNKNOWN_FIELD",
        )

    for key in REQUIRED_ACTION_FIELDS:
        if raw_dict[key] is None:
            raise SchemaValidationError(
                f"Required action field {key!r} cannot be null.",
                error_code="EXPLICIT_NULL_NOT_ALLOWED",
            )

    schema_version = _validate_schema_version(raw_dict["schema_version"])
    tenant_id = _validate_identifier(raw_dict["tenant_id"], "tenant_id")
    principal_id = _validate_identifier(raw_dict["principal_id"], "principal_id")
    tool = _validate_identifier(raw_dict["tool"], "tool")
    resource = _validate_identifier(raw_dict["resource"], "resource")
    environment = _validate_identifier(raw_dict["environment"], "environment")
    policy_version = _validate_policy_version(raw_dict["policy_version"])
    intent_id = _validate_identifier(raw_dict["intent_id"], "intent_id")

    raw_arguments = raw_dict["arguments"]
    if not isinstance(raw_arguments, Mapping):
        raise SchemaValidationError(
            f"Field 'arguments' must be a JSON object/mapping, got {type(raw_arguments).__name__}.",
            error_code="INVALID_FIELD_TYPE",
        )
    arguments = _normalize_argument_value(raw_arguments, "arguments", depth=1)

    return CanonicalAction(
        schema_version=schema_version,
        tenant_id=tenant_id,
        principal_id=principal_id,
        tool=tool,
        resource=resource,
        arguments=arguments,
        environment=environment,
        policy_version=policy_version,
        intent_id=intent_id,
    )


def canonicalize_json_object(obj: Any) -> bytes:
    """Serialize a validated Python object into deterministic RFC 8785 / JCS-compatible UTF-8 bytes."""
    canonical_str = json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return canonical_str.encode("utf-8")


def canonicalize_action(
    action: Union[Mapping[str, Any], CanonicalAction, str, bytes, bytearray],
) -> bytes:
    """Validate an action and produce deterministic canonical UTF-8 bytes."""
    validated = validate_and_normalize_action(action)
    return validated.canonical_bytes()
