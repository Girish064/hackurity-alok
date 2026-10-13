"""
security/receipts/signer.py
Signed execution receipt issuance.

The receipt is a signed JWT binding:
  capability_id, action_digest, executor_id, outcome, executed_at
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

ALGORITHM = "EdDSA"


def sign_execution_receipt(
    capability_id: str,
    action_digest: str,
    executor_id: str,
    outcome: str,           # "SUCCESS" | "FAILURE" | "TOOL_ERROR"
    outcome_data: dict,
    executed_at: str,       # ISO-8601 UTC
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> str:
    """
    Sign an execution receipt JWT and return the compact token string.
    The receipt is non-repudiation evidence that the executor ran this
    exact capability with this exact outcome.
    """
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "jti": str(uuid.uuid4()),
        "iat": now,
        "capability_id": capability_id,
        "action_digest": action_digest,
        "executor_id": executor_id,
        "outcome": outcome,
        "outcome_data": outcome_data,
        "executed_at": executed_at,
    }
    headers = {"kid": key_id}
    return jwt.encode(payload, signing_key, algorithm=ALGORITHM, headers=headers)
