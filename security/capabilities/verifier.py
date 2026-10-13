"""
security/capabilities/verifier.py
Ed25519 JWT capability verification.

Verification checks (all must pass — fail on any):
  1. Signature valid (Ed25519).
  2. Token not expired (exp claim).
  3. sub == expected_agent_id.
  4. tenant_id claim == expected_tenant_id.
  5. action_digest claim == expected_action_digest.
  6. executor_id claim == expected_executor_id.
"""
from __future__ import annotations

from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import jwt
from jwt.exceptions import ExpiredSignatureError, PyJWTError

from security.exceptions import CapabilityExpiredError, CapabilityVerificationError
from security.schemas import CapabilityClaims

ALGORITHM = "EdDSA"


def verify_capability(
    token: str,
    expected_agent_id: str,
    expected_tenant_id: str,
    expected_action_digest: str,
    expected_executor_id: str,
    verifying_key: Ed25519PublicKey,
    now: datetime | None = None,
) -> CapabilityClaims:
    """
    Verify the capability token and return its claims.
    Raises CapabilityExpiredError or CapabilityVerificationError on any failure.
    The `now` parameter is injectable for deterministic testing.
    """
    try:
        if now is not None:
            claims = jwt.decode(
                token,
                verifying_key,
                algorithms=[ALGORITHM],
                options={"verify_exp": False},
            )
            now_ts = int(now.timestamp())
            if claims.get("exp", 0) <= now_ts:
                raise CapabilityExpiredError("Capability token has expired.")
        else:
            claims = jwt.decode(
                token,
                verifying_key,
                algorithms=[ALGORITHM],
                options={"verify_exp": True},
            )
    except ExpiredSignatureError as exc:
        raise CapabilityExpiredError("Capability token has expired.") from exc
    except PyJWTError as exc:
        raise CapabilityVerificationError(
            f"Capability token signature or structure invalid: {exc}"
        ) from exc

    # Binding checks — each failure is a distinct security violation
    errors: list[str] = []

    if claims.get("sub") != expected_agent_id:
        errors.append(
            f"agent_id mismatch: got {claims.get('sub')!r}, "
            f"expected {expected_agent_id!r}"
        )
    if claims.get("tenant_id") != expected_tenant_id:
        errors.append(
            f"tenant_id mismatch: got {claims.get('tenant_id')!r}, "
            f"expected {expected_tenant_id!r}"
        )
    if claims.get("action_digest") != expected_action_digest:
        errors.append("action_digest mismatch — action may have been modified")
    if claims.get("executor_id") != expected_executor_id:
        errors.append(
            f"executor_id mismatch: got {claims.get('executor_id')!r}, "
            f"expected {expected_executor_id!r}"
        )

    if errors:
        raise CapabilityVerificationError(
            "Capability binding verification failed: " + "; ".join(errors)
        )

    exp_dt = datetime.fromtimestamp(claims["exp"], tz=timezone.utc)
    iat_dt = datetime.fromtimestamp(claims["iat"], tz=timezone.utc)

    return CapabilityClaims(
        capability_id=claims["jti"],
        agent_id=claims["sub"],
        tenant_id=claims["tenant_id"],
        action_digest=claims["action_digest"],
        executor_id=claims["executor_id"],
        expires_at=exp_dt,
        approval_ref=claims.get("approval_ref"),
        issued_at=iat_dt,
    )
