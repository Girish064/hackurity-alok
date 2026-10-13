"""
security/receipts/verifier.py
Execution receipt verification.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
import jwt
from jwt.exceptions import PyJWTError

from security.exceptions import ReceiptVerificationError

ALGORITHM = "EdDSA"


@dataclass
class ExecutionReceiptClaims:
    capability_id: str
    action_digest: str
    executor_id: str
    outcome: str
    outcome_data: dict
    executed_at: str


def verify_execution_receipt(
    receipt_token: str,
    verifying_key: Ed25519PublicKey,
) -> ExecutionReceiptClaims:
    """
    Verify the execution receipt JWT and return its claims.
    Raises ReceiptVerificationError on any failure.
    """
    try:
        claims = jwt.decode(
            receipt_token,
            verifying_key,
            algorithms=[ALGORITHM],
            options={"verify_exp": False},  # receipts have no expiry
        )
    except PyJWTError as exc:
        raise ReceiptVerificationError(
            f"Execution receipt verification failed: {exc}"
        ) from exc

    return ExecutionReceiptClaims(
        capability_id=claims["capability_id"],
        action_digest=claims["action_digest"],
        executor_id=claims["executor_id"],
        outcome=claims["outcome"],
        outcome_data=claims.get("outcome_data", {}),
        executed_at=claims["executed_at"],
    )
