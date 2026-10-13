"""Component B — Cryptographically Signed, Action-Bound Capabilities for AgentShield V2.

Implements Ed25519-signed JWS capabilities (`typ: "agentshield-capability+jwt"`)
that bind permission to execute one specifically authorized canonical action.

Security invariants:
- A valid signature alone is NEVER sufficient permission to execute.
- The protected executor independently verifies:
  1. Ed25519 signature validity and trusted, active capability signing key (kid).
  2. Correct issuer (iss) and audience (aud).
  3. Issued-at (iat), expiry (exp), and bounded TTL with clock-skew checks.
  4. Authenticated caller identity matches principal_id (sub).
  5. Exact match of tenant_id, tool, resource, environment, policy_version, intent_id,
     and recomputed SHA-256 action_digest of the requested action.
  6. Fail-closed verification context (healthy policy, revocation, and replay dependencies).
  7. Principal/capability revocation state at execution time.
  8. Valid, action-bound, single-use human approval when required.
  9. Atomic one-time capability JTI claim (replay protection).
"""

from __future__ import annotations

import hmac
import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Union

from .action_digest import calculate_action_digest, is_valid_sha256_hex
from .approval_binding import (
    ApprovalConsumptionStore,
    ApprovalRecord,
    ApprovalVerificationError,
    verify_approval,
)
from .canonicalization import (
    CanonicalAction,
    CanonicalizationError,
    _validate_identifier,
    _validate_policy_version,
    canonicalize_json_object,
    coerce_to_mapping,
    parse_strict_json,
    validate_and_normalize_action,
)
from .key_management import (
    KeyManagementError,
    KeyManager,
    KeyPurpose,
    ManagedKey,
    b64url_decode,
    b64url_encode,
    create_default_key_manager,
)

DEFAULT_CAPABILITY_ISSUER: str = "agentshield-gateway"
DEFAULT_CAPABILITY_AUDIENCE: str = "agentshield-executor"
CAPABILITY_TOKEN_TYP: str = "agentshield-capability+jwt"
CAPABILITY_ALG: str = "EdDSA"
DEFAULT_CAPABILITY_TTL_SECONDS: int = 60
MAX_CAPABILITY_TTL_SECONDS: int = 300
DEFAULT_CLOCK_SKEW_SECONDS: int = 5

from .exceptions import AgentShieldSecurityError


class CapabilityVerificationError(AgentShieldSecurityError):
    """Raised when capability issuance or executor-side verification fails."""

    def __init__(self, message: str, error_code: str = "CAPABILITY_VERIFICATION_FAILED") -> None:
        super().__init__(message, error_code=error_code)


class CapabilityExpiredError(CapabilityVerificationError):
    """Raised when a capability token has expired."""

    def __init__(self, message: str = "Capability token has expired.", error_code: str = "CAPABILITY_EXPIRED") -> None:
        super().__init__(message, error_code=error_code)


class ReplayProtectionStore:
    """Thread-safe atomic JTI replay store (simulates Redis SET NX EX for unit/adversarial tests
    and wraps optional Redis client for integrated deployment).
    """

    def __init__(self, redis_client: Optional[Any] = None) -> None:
        self._lock = threading.Lock()
        self._claimed: dict[str, int] = {}
        self._redis = redis_client

    def claim(self, jti: str, expires_at: int, now: Optional[int] = None) -> bool:
        """Atomically claim a capability JTI until expires_at.

        Returns True strictly on the first claim; False on any concurrent or subsequent replay.
        """
        if not jti or not isinstance(jti, str):
            raise CapabilityVerificationError(
                "Invalid capability JTI for atomic claim.",
                error_code="INVALID_CAPABILITY_JTI",
            )
        current_time = now if now is not None else int(time.time())
        ttl = max(1, expires_at - current_time + 60)

        if self._redis is not None:
            try:
                result = self._redis.set(f"agentshield:cap:jti:{jti}", "CLAIMED", nx=True, ex=ttl)
                return bool(result)
            except Exception as exc:
                raise CapabilityVerificationError(
                    f"Replay store dependency failure during atomic JTI claim: {exc}",
                    error_code="DEPENDENCY_OUTAGE_FAIL_CLOSED",
                ) from exc

        with self._lock:
            # Prune expired entries
            expired_keys = [k for k, exp in self._claimed.items() if exp < current_time]
            for k in expired_keys:
                del self._claimed[k]

            if jti in self._claimed:
                return False
            self._claimed[jti] = current_time + ttl
            return True

    def is_claimed(self, jti: str, now: Optional[int] = None) -> bool:
        """Check whether a capability JTI is currently claimed."""
        current_time = now if now is not None else int(time.time())
        with self._lock:
            exp = self._claimed.get(jti)
            if exp is None:
                return False
            if exp < current_time:
                del self._claimed[jti]
                return False
            return True

    def reset(self) -> None:
        """Clear all claimed JTIs (for demo reset / test isolation)."""
        with self._lock:
            self._claimed.clear()


@dataclass(frozen=True)
class CapabilityClaims:
    """Validated claims bound inside an AgentShield V2 capability token."""

    iss: str
    aud: str
    sub: str
    principal_id: str
    tenant_id: str
    tool: str
    resource: str
    action_digest: str
    jti: str
    iat: int
    exp: int
    policy_version: Union[int, str]
    environment: str
    intent_id: str
    kid: str
    approval_id: Optional[str] = None
    schema_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        """Serialize claims to a canonical dictionary."""
        return {
            "action_digest": self.action_digest,
            "approval_id": self.approval_id,
            "aud": self.aud,
            "environment": self.environment,
            "exp": self.exp,
            "iat": self.iat,
            "intent_id": self.intent_id,
            "iss": self.iss,
            "jti": self.jti,
            "kid": self.kid,
            "policy_version": self.policy_version,
            "principal_id": self.principal_id,
            "resource": self.resource,
            "schema_version": self.schema_version,
            "sub": self.sub,
            "tenant_id": self.tenant_id,
            "tool": self.tool,
        }

    def __getitem__(self, key: str) -> Any:
        return self.to_dict()[key]


@dataclass(frozen=True)
class VerifiedCapabilityClaims:
    """Structured result returned by `verify_capability` upon full executor verification."""

    valid: bool
    claims: CapabilityClaims
    approval_verified: bool = False
    claimed_atomically: bool = False

    @property
    def is_valid(self) -> bool:
        return self.valid

    @property
    def jti(self) -> str:
        return self.claims.jti

    @property
    def action_digest(self) -> str:
        return self.claims.action_digest

    @property
    def tenant_id(self) -> str:
        return self.claims.tenant_id

    @property
    def principal_id(self) -> str:
        return self.claims.principal_id

    @property
    def tool(self) -> str:
        return self.claims.tool

    @property
    def resource(self) -> str:
        return self.claims.resource

    @property
    def environment(self) -> str:
        return self.claims.environment

    @property
    def policy_version(self) -> Union[int, str]:
        return self.claims.policy_version

    @property
    def intent_id(self) -> str:
        return self.claims.intent_id

    @property
    def approval_id(self) -> Optional[str]:
        return self.claims.approval_id

    @property
    def kid(self) -> str:
        return self.claims.kid

    def __getitem__(self, item: str) -> Any:
        return self.claims[item]

    def __bool__(self) -> bool:
        return self.valid


@dataclass
class VerificationContext:
    """Executor verification context containing key store, replay store, revocation state,
    policy context, and approval records.

    If any critical dependency flag is False, `verify_capability` fails closed immediately.
    """

    key_manager: Optional[KeyManager] = None
    replay_store: Optional[ReplayProtectionStore] = None
    approval_consumption_store: Optional[ApprovalConsumptionStore] = None
    expected_issuer: str = DEFAULT_CAPABILITY_ISSUER
    expected_audience: str = DEFAULT_CAPABILITY_AUDIENCE
    active_policy_version: Optional[Union[int, str]] = None
    revoked_principals: set[str] = field(default_factory=set)
    revoked_jtis: set[str] = field(default_factory=set)
    revoked_tenants: set[str] = field(default_factory=set)
    is_principal_revoked_fn: Optional[Callable[[str], bool]] = None
    approval_required: bool = False
    approval: Optional[Union[ApprovalRecord, Mapping[str, Any]]] = None
    now: Optional[int] = None
    clock_skew_seconds: int = DEFAULT_CLOCK_SKEW_SECONDS
    max_ttl_seconds: int = MAX_CAPABILITY_TTL_SECONDS
    allow_retired_keys: bool = False
    # Critical dependency health flags (fail-closed if any is False)
    dependencies_healthy: bool = True
    policy_service_available: bool = True
    revocation_store_available: bool = True
    replay_store_available: bool = True


def build_capability_claims_from_action(
    action: Union[Mapping[str, Any], CanonicalAction, str, bytes],
    *,
    kid: str,
    jti: Optional[str] = None,
    iat: Optional[int] = None,
    exp: Optional[int] = None,
    ttl_seconds: int = DEFAULT_CAPABILITY_TTL_SECONDS,
    approval_id: Optional[str] = None,
    iss: str = DEFAULT_CAPABILITY_ISSUER,
    aud: str = DEFAULT_CAPABILITY_AUDIENCE,
) -> CapabilityClaims:
    """Build a CapabilityClaims instance directly from a validated canonical action."""
    validated_action = validate_and_normalize_action(action)
    digest = calculate_action_digest(validated_action)
    now_ts = iat if iat is not None else int(time.time())
    exp_ts = exp if exp is not None else (now_ts + ttl_seconds)

    if exp_ts <= now_ts:
        raise CapabilityVerificationError(
            f"Capability exp ({exp_ts}) must be strictly greater than iat ({now_ts}).",
            error_code="INVALID_CAPABILITY_TIMESTAMPS",
        )
    if (exp_ts - now_ts) > MAX_CAPABILITY_TTL_SECONDS:
        raise CapabilityVerificationError(
            f"Capability TTL ({exp_ts - now_ts}s) exceeds maximum allowed ({MAX_CAPABILITY_TTL_SECONDS}s).",
            error_code="CAPABILITY_TTL_TOO_LONG",
        )

    norm_approval_id = (
        _validate_identifier(approval_id, "approval_id") if approval_id is not None else None
    )

    return CapabilityClaims(
        iss=_validate_identifier(iss, "iss"),
        aud=_validate_identifier(aud, "aud"),
        sub=validated_action.principal_id,
        principal_id=validated_action.principal_id,
        tenant_id=validated_action.tenant_id,
        tool=validated_action.tool,
        resource=validated_action.resource,
        action_digest=digest,
        jti=_validate_identifier(jti or f"cap-{uuid.uuid4().hex}", "jti"),
        iat=now_ts,
        exp=exp_ts,
        policy_version=validated_action.policy_version,
        environment=validated_action.environment,
        intent_id=validated_action.intent_id,
        kid=_validate_identifier(kid, "kid"),
        approval_id=norm_approval_id,
        schema_version=validated_action.schema_version,
    )


def issue_capability(
    claims: Any,
    signing_key: Optional[Union[ManagedKey, KeyManager]] = None,
    *,
    ttl_seconds: int = DEFAULT_CAPABILITY_TTL_SECONDS,
) -> str:
    """Issue an Ed25519-signed capability token in Compact JWS format (`header.payload.signature`).

    `claims` may be:
    - A `CapabilityClaims` instance
    - A dictionary or Pydantic model containing `"action"` (plus optional `jti`, `iat`, `exp`, `approval_id`, `iss`, `aud`)
    - An action dictionary or Pydantic model itself (containing `"arguments"`, `"tool"`, etc.)
    - A dictionary of explicit capability claim fields (`action_digest`, `tenant_id`, `principal_id`, etc.)
    """
    if signing_key is None:
        signing_key = create_default_key_manager().get_signing_key(purpose=KeyPurpose.CAPABILITY)
    elif isinstance(signing_key, KeyManager):
        signing_key = signing_key.get_signing_key(purpose=KeyPurpose.CAPABILITY)
    elif not isinstance(signing_key, ManagedKey):
        raise CapabilityVerificationError(
            "signing_key must be a ManagedKey or KeyManager instance.",
            error_code="INVALID_SIGNING_KEY",
        )
    if signing_key.purpose not in {KeyPurpose.CAPABILITY, KeyPurpose.ALL}:
        raise CapabilityVerificationError(
            f"Key {signing_key.kid!r} has purpose {signing_key.purpose.value!r}, cannot issue capabilities.",
            error_code="KEY_PURPOSE_MISMATCH",
        )

    if isinstance(claims, CapabilityClaims):
        if claims.kid != signing_key.kid:
            raise CapabilityVerificationError(
                f"CapabilityClaims kid {claims.kid!r} does not match signing_key kid {signing_key.kid!r}.",
                error_code="KID_MISMATCH",
            )
        cap_claims = claims
    else:
        try:
            claims_map = coerce_to_mapping(claims)
        except CanonicalizationError as exc:
            raise CapabilityVerificationError(
                "claims must be a CapabilityClaims instance, Mapping, or Pydantic model.",
                error_code="INVALID_CLAIMS_TYPE",
            ) from exc

        if "action" in claims_map and claims_map["action"] is not None:
            cap_claims = build_capability_claims_from_action(
                claims_map["action"],
                kid=signing_key.kid,
                jti=claims_map.get("jti"),
                iat=claims_map.get("iat"),
                exp=claims_map.get("exp"),
                ttl_seconds=claims_map.get("ttl_seconds", ttl_seconds),
                approval_id=claims_map.get("approval_id"),
                iss=claims_map.get("iss", DEFAULT_CAPABILITY_ISSUER),
                aud=claims_map.get("aud", DEFAULT_CAPABILITY_AUDIENCE),
            )
        elif "arguments" in claims_map and "action_digest" not in claims_map:
            cap_claims = build_capability_claims_from_action(
                claims_map,
                kid=signing_key.kid,
                ttl_seconds=ttl_seconds,
            )
        else:
            now_ts = claims_map.get("iat", int(time.time()))
            exp_ts = claims_map.get("exp", now_ts + ttl_seconds)
            if isinstance(now_ts, bool) or not isinstance(now_ts, int):
                raise CapabilityVerificationError("iat must be an integer timestamp.", error_code="INVALID_CLAIM")
            if isinstance(exp_ts, bool) or not isinstance(exp_ts, int):
                raise CapabilityVerificationError("exp must be an integer timestamp.", error_code="INVALID_CLAIM")
            if exp_ts <= now_ts:
                raise CapabilityVerificationError(
                    "Capability exp must be strictly greater than iat.",
                    error_code="INVALID_CAPABILITY_TIMESTAMPS",
                )
            if (exp_ts - now_ts) > MAX_CAPABILITY_TTL_SECONDS:
                raise CapabilityVerificationError(
                    f"Capability TTL ({exp_ts - now_ts}s) exceeds max {MAX_CAPABILITY_TTL_SECONDS}s.",
                    error_code="CAPABILITY_TTL_TOO_LONG",
                )
            principal = claims_map.get("principal_id") or claims_map.get("sub")
            if not principal:
                raise CapabilityVerificationError(
                    "Missing 'principal_id' (or 'sub') in capability claims.",
                    error_code="MISSING_CLAIM",
                )
            norm_principal = _validate_identifier(principal, "principal_id")
            sub_val = _validate_identifier(claims_map.get("sub", norm_principal), "sub")
            if sub_val != norm_principal:
                raise CapabilityVerificationError(
                    "Capability 'sub' and 'principal_id' must match.",
                    error_code="PRINCIPAL_MISMATCH",
                )
            digest = claims_map.get("action_digest")
            if not is_valid_sha256_hex(digest):
                raise CapabilityVerificationError(
                    f"Invalid or missing 64-char SHA-256 'action_digest': {digest!r}",
                    error_code="INVALID_ACTION_DIGEST",
                )
            claim_kid = claims_map.get("kid", signing_key.kid)
            if claim_kid != signing_key.kid:
                raise CapabilityVerificationError(
                    f"Claim kid {claim_kid!r} does not match signing_key kid {signing_key.kid!r}.",
                    error_code="KID_MISMATCH",
                )
            approval_id_val = claims_map.get("approval_id")
            norm_appr = (
                _validate_identifier(approval_id_val, "approval_id")
                if approval_id_val is not None
                else None
            )
            cap_claims = CapabilityClaims(
                iss=_validate_identifier(claims_map.get("iss", DEFAULT_CAPABILITY_ISSUER), "iss"),
                aud=_validate_identifier(claims_map.get("aud", DEFAULT_CAPABILITY_AUDIENCE), "aud"),
                sub=sub_val,
                principal_id=norm_principal,
                tenant_id=_validate_identifier(claims_map["tenant_id"], "tenant_id"),
                tool=_validate_identifier(claims_map["tool"], "tool"),
                resource=_validate_identifier(claims_map["resource"], "resource"),
                action_digest=digest,
                jti=_validate_identifier(claims_map.get("jti") or f"cap-{uuid.uuid4().hex}", "jti"),
                iat=now_ts,
                exp=exp_ts,
                policy_version=_validate_policy_version(claims_map["policy_version"]),
                environment=_validate_identifier(claims_map["environment"], "environment"),
                intent_id=_validate_identifier(claims_map["intent_id"], "intent_id"),
                kid=signing_key.kid,
                approval_id=norm_appr,
                schema_version=int(claims_map.get("schema_version", 1)),
            )

    header = {
        "alg": CAPABILITY_ALG,
        "kid": signing_key.kid,
        "typ": CAPABILITY_TOKEN_TYP,
    }
    header_b64 = b64url_encode(canonicalize_json_object(header))
    payload_b64 = b64url_encode(canonicalize_json_object(cap_claims.to_dict()))
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

    try:
        signature_bytes = signing_key.sign(signing_input)
    except KeyManagementError as exc:
        raise CapabilityVerificationError(str(exc), error_code=exc.error_code) from exc

    sig_b64 = b64url_encode(signature_bytes)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_capability(
    signed_capability: str,
    expected_action: Any,
    authenticated_principal: str,
    verification_context: Optional[Union[VerificationContext, Mapping[str, Any]]] = None,
) -> VerifiedCapabilityClaims:
    """Independently verify a signed capability at the protected executor boundary.

    Raises `CapabilityVerificationError` with a specific `error_code` if ANY verification
    step fails. Never silently accepts invalid data or missing context.
    """
    # 1. Fail-closed check on verification_context and critical dependencies
    if verification_context is None:
        raise CapabilityVerificationError(
            "Missing critical verification_context; protected executor must fail closed.",
            error_code="MISSING_VERIFICATION_CONTEXT",
        )

    if isinstance(verification_context, Mapping):
        try:
            ctx = VerificationContext(**verification_context)
        except TypeError as exc:
            raise CapabilityVerificationError(
                f"Invalid verification_context parameters: {exc}",
                error_code="INVALID_VERIFICATION_CONTEXT",
            ) from exc
    elif isinstance(verification_context, VerificationContext):
        ctx = verification_context
    else:
        raise CapabilityVerificationError(
            "verification_context must be a VerificationContext or Mapping.",
            error_code="INVALID_VERIFICATION_CONTEXT",
        )

    if (
        not ctx.dependencies_healthy
        or not ctx.policy_service_available
        or not ctx.revocation_store_available
        or not ctx.replay_store_available
    ):
        raise CapabilityVerificationError(
            "Critical security dependency (policy, revocation, or replay store) is unavailable; failing closed.",
            error_code="DEPENDENCY_OUTAGE_FAIL_CLOSED",
        )

    effective_key_manager = (
        ctx.key_manager
        if ctx.key_manager is not None
        else create_default_key_manager().public_verifier_store()
    )

    if not authenticated_principal or not isinstance(authenticated_principal, str):
        raise CapabilityVerificationError(
            "Missing or unauthenticated caller principal.",
            error_code="UNAUTHENTICATED_PRINCIPAL",
        )
    norm_caller = _validate_identifier(authenticated_principal, "authenticated_principal")

    # 2. Validate and canonicalize expected_action
    try:
        canonical_expected_action = validate_and_normalize_action(expected_action)
        expected_digest = calculate_action_digest(canonical_expected_action)
    except CanonicalizationError as exc:
        raise CapabilityVerificationError(
            f"Requested action failed canonical validation: {exc}",
            error_code=exc.error_code,
        ) from exc

    # 3. Parse Compact JWS envelope
    if not isinstance(signed_capability, str) or signed_capability.count(".") != 2:
        raise CapabilityVerificationError(
            "Malformed capability token: expected 3 dot-separated JWS segments.",
            error_code="MALFORMED_CAPABILITY_TOKEN",
        )

    header_b64, payload_b64, sig_b64 = signed_capability.split(".")
    if not header_b64 or not payload_b64 or not sig_b64:
        raise CapabilityVerificationError(
            "Malformed capability token: empty JWS segment.",
            error_code="MALFORMED_CAPABILITY_TOKEN",
        )

    try:
        header_bytes = b64url_decode(header_b64)
        payload_bytes = b64url_decode(payload_b64)
        signature_bytes = b64url_decode(sig_b64)
        header = parse_strict_json(header_bytes)
        payload = parse_strict_json(payload_bytes)
    except Exception as exc:
        raise CapabilityVerificationError(
            f"Failed to decode capability token segments: {exc}",
            error_code="MALFORMED_CAPABILITY_TOKEN",
        ) from exc

    # 4. Validate JWS header & algorithm
    if header.get("alg") != CAPABILITY_ALG:
        raise CapabilityVerificationError(
            f"Unsupported or insecure JWS algorithm: {header.get('alg')!r}; expected {CAPABILITY_ALG!r}.",
            error_code="UNSUPPORTED_ALGORITHM",
        )
    if header.get("typ") != CAPABILITY_TOKEN_TYP:
        raise CapabilityVerificationError(
            f"Invalid token type {header.get('typ')!r}; expected {CAPABILITY_TOKEN_TYP!r}.",
            error_code="INVALID_TOKEN_TYPE",
        )
    header_kid = header.get("kid")
    payload_kid = payload.get("kid")
    if not header_kid or not isinstance(header_kid, str):
        raise CapabilityVerificationError(
            "Capability header is missing 'kid'.",
            error_code="MISSING_KEY_ID",
        )
    if payload_kid != header_kid:
        raise CapabilityVerificationError(
            f"Capability header kid ({header_kid!r}) does not match payload kid ({payload_kid!r}).",
            error_code="KID_MISMATCH",
        )

    # 5. Extract and validate payload timestamps before key verification
    raw_iat = payload.get("iat")
    raw_exp = payload.get("exp")
    if isinstance(raw_iat, bool) or not isinstance(raw_iat, int):
        raise CapabilityVerificationError("Invalid 'iat' claim in capability.", error_code="INVALID_CLAIM")
    if isinstance(raw_exp, bool) or not isinstance(raw_exp, int):
        raise CapabilityVerificationError("Invalid 'exp' claim in capability.", error_code="INVALID_CLAIM")

    # 6. Resolve trusted verification key and verify Ed25519 signature
    try:
        ver_key = effective_key_manager.get_verification_key(
            header_kid,
            purpose=KeyPurpose.CAPABILITY,
            record_timestamp=raw_iat,
            allow_retired=ctx.allow_retired_keys,
            clock_skew_seconds=ctx.clock_skew_seconds,
        )
    except KeyManagementError as exc:
        raise CapabilityVerificationError(str(exc), error_code=exc.error_code) from exc

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    if not ver_key.verify_signature(signature_bytes, signing_input):
        raise CapabilityVerificationError(
            "Capability Ed25519 signature verification failed.",
            error_code="INVALID_CAPABILITY_SIGNATURE",
        )

    # 7. Parse structured claims
    try:
        claims = CapabilityClaims(
            iss=_validate_identifier(payload["iss"], "iss"),
            aud=_validate_identifier(payload["aud"], "aud"),
            sub=_validate_identifier(payload["sub"], "sub"),
            principal_id=_validate_identifier(payload["principal_id"], "principal_id"),
            tenant_id=_validate_identifier(payload["tenant_id"], "tenant_id"),
            tool=_validate_identifier(payload["tool"], "tool"),
            resource=_validate_identifier(payload["resource"], "resource"),
            action_digest=str(payload["action_digest"]),
            jti=_validate_identifier(payload["jti"], "jti"),
            iat=raw_iat,
            exp=raw_exp,
            policy_version=_validate_policy_version(payload["policy_version"]),
            environment=_validate_identifier(payload["environment"], "environment"),
            intent_id=_validate_identifier(payload["intent_id"], "intent_id"),
            kid=header_kid,
            approval_id=(
                _validate_identifier(payload["approval_id"], "approval_id")
                if payload.get("approval_id") is not None
                else None
            ),
            schema_version=int(payload.get("schema_version", 1)),
        )
    except (KeyError, ValueError, CanonicalizationError) as exc:
        raise CapabilityVerificationError(
            f"Invalid capability payload claims: {exc}",
            error_code="INVALID_CAPABILITY_CLAIMS",
        ) from exc

    # 8. Verify issuer and audience
    if claims.iss != ctx.expected_issuer:
        raise CapabilityVerificationError(
            f"Invalid capability issuer {claims.iss!r}; expected {ctx.expected_issuer!r}.",
            error_code="INVALID_ISSUER",
        )
    if claims.aud != ctx.expected_audience:
        raise CapabilityVerificationError(
            f"Invalid capability audience {claims.aud!r}; expected {ctx.expected_audience!r}.",
            error_code="INVALID_AUDIENCE",
        )

    # 9. Verify time window (iat, exp, TTL, clock skew)
    current_time = ctx.now if ctx.now is not None else int(time.time())
    if claims.exp <= claims.iat:
        raise CapabilityVerificationError(
            "Capability exp must be greater than iat.",
            error_code="INVALID_CAPABILITY_TIMESTAMPS",
        )
    if (claims.exp - claims.iat) > ctx.max_ttl_seconds:
        raise CapabilityVerificationError(
            f"Capability lifetime ({claims.exp - claims.iat}s) exceeds maximum allowed ({ctx.max_ttl_seconds}s).",
            error_code="CAPABILITY_TTL_TOO_LONG",
        )
    if claims.iat > current_time + ctx.clock_skew_seconds:
        raise CapabilityVerificationError(
            f"Capability issued in the future: iat={claims.iat}, now={current_time}.",
            error_code="CAPABILITY_ISSUED_IN_FUTURE",
        )
    if current_time > claims.exp + ctx.clock_skew_seconds:
        raise CapabilityVerificationError(
            f"Capability expired at {claims.exp} (now={current_time}).",
            error_code="CAPABILITY_EXPIRED",
        )

    # 10. Verify caller identity matches capability principal AND action principal
    if claims.sub != claims.principal_id:
        raise CapabilityVerificationError(
            "Capability sub and principal_id claims do not match.",
            error_code="PRINCIPAL_MISMATCH",
        )
    if claims.principal_id != norm_caller:
        raise CapabilityVerificationError(
            f"Authenticated caller {norm_caller!r} does not match capability principal {claims.principal_id!r}.",
            error_code="PRINCIPAL_MISMATCH",
        )
    if canonical_expected_action.principal_id != norm_caller:
        raise CapabilityVerificationError(
            f"Action principal {canonical_expected_action.principal_id!r} does not match authenticated caller {norm_caller!r}.",
            error_code="PRINCIPAL_MISMATCH",
        )

    # 11. Verify exact action binding (digest + all individual contextual fields)
    if not is_valid_sha256_hex(claims.action_digest) or not hmac.compare_digest(
        claims.action_digest, expected_digest
    ):
        raise CapabilityVerificationError(
            f"Capability action_digest ({claims.action_digest[:16]}...) does not match "
            f"requested action digest ({expected_digest[:16]}...).",
            error_code="ACTION_DIGEST_MISMATCH",
        )

    if claims.tenant_id != canonical_expected_action.tenant_id:
        raise CapabilityVerificationError(
            f"Capability tenant_id {claims.tenant_id!r} does not match action tenant_id {canonical_expected_action.tenant_id!r}.",
            error_code="TENANT_MISMATCH",
        )
    if claims.tool != canonical_expected_action.tool:
        raise CapabilityVerificationError(
            f"Capability tool {claims.tool!r} does not match action tool {canonical_expected_action.tool!r}.",
            error_code="TOOL_MISMATCH",
        )
    if claims.resource != canonical_expected_action.resource:
        raise CapabilityVerificationError(
            f"Capability resource {claims.resource!r} does not match action resource {canonical_expected_action.resource!r}.",
            error_code="RESOURCE_MISMATCH",
        )
    if claims.environment != canonical_expected_action.environment:
        raise CapabilityVerificationError(
            f"Capability environment {claims.environment!r} does not match action environment {canonical_expected_action.environment!r}.",
            error_code="ENVIRONMENT_MISMATCH",
        )
    if claims.policy_version != canonical_expected_action.policy_version:
        raise CapabilityVerificationError(
            f"Capability policy_version {claims.policy_version!r} does not match action policy_version {canonical_expected_action.policy_version!r}.",
            error_code="POLICY_VERSION_MISMATCH",
        )
    if claims.intent_id != canonical_expected_action.intent_id:
        raise CapabilityVerificationError(
            f"Capability intent_id {claims.intent_id!r} does not match action intent_id {canonical_expected_action.intent_id!r}.",
            error_code="INTENT_ID_MISMATCH",
        )

    # 12. Verify active policy context and revocation status
    if ctx.active_policy_version is not None and claims.policy_version != ctx.active_policy_version:
        raise CapabilityVerificationError(
            f"Capability policy_version {claims.policy_version!r} does not match active policy version {ctx.active_policy_version!r}.",
            error_code="STALE_POLICY_VERSION",
        )

    if claims.tenant_id in ctx.revoked_tenants:
        raise CapabilityVerificationError(
            f"Tenant {claims.tenant_id!r} has been revoked.",
            error_code="TENANT_REVOKED",
        )

    if claims.principal_id in ctx.revoked_principals or (
        ctx.is_principal_revoked_fn is not None and ctx.is_principal_revoked_fn(claims.principal_id)
    ):
        raise CapabilityVerificationError(
            f"Principal {claims.principal_id!r} has been revoked prior to execution.",
            error_code="PRINCIPAL_REVOKED",
        )

    if claims.jti in ctx.revoked_jtis:
        raise CapabilityVerificationError(
            f"Capability {claims.jti!r} has been explicitly revoked.",
            error_code="CAPABILITY_REVOKED",
        )

    # 13. Verify human approval if required by policy or present in context
    approval_verified = False
    if ctx.approval_required or ctx.approval is not None or claims.approval_id is not None:
        if ctx.approval_required and not claims.approval_id:
            raise CapabilityVerificationError(
                "Human approval is required for this action, but capability has no approval_id.",
                error_code="MISSING_REQUIRED_APPROVAL",
            )
        if ctx.approval_required and ctx.approval is None:
            raise CapabilityVerificationError(
                "Human approval is required for this action, but no approval record was supplied in verification_context.",
                error_code="MISSING_REQUIRED_APPROVAL",
            )
        if ctx.approval is not None:
            try:
                verify_approval(
                    ctx.approval,
                    expected_digest,
                    expected_action=canonical_expected_action,
                    expected_tenant_id=claims.tenant_id,
                    expected_request_id=claims.intent_id,
                    expected_approval_id=claims.approval_id,
                    expected_principal_id=claims.principal_id,
                    key_manager=effective_key_manager,
                    now=current_time,
                    clock_skew_seconds=ctx.clock_skew_seconds,
                    consume=True,
                    consumption_store=ctx.approval_consumption_store,
                    raise_on_error=True,
                )
                approval_verified = True
            except ApprovalVerificationError as exc:
                raise CapabilityVerificationError(
                    f"Approval verification failed: {exc}",
                    error_code=exc.error_code,
                ) from exc

    # 14. Atomically claim capability JTI in replay store
    claimed_atomically = False
    if ctx.replay_store is not None:
        if not ctx.replay_store.claim(claims.jti, claims.exp, now=current_time):
            raise CapabilityVerificationError(
                f"Capability {claims.jti!r} has already been claimed/consumed (replay detected).",
                error_code="CAPABILITY_REPLAY_DETECTED",
            )
        claimed_atomically = True

    return VerifiedCapabilityClaims(
        valid=True,
        claims=claims,
        approval_verified=approval_verified,
        claimed_atomically=claimed_atomically,
    )
