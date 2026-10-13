"""
security/capabilities/issuer.py
Ed25519-signed JWT capability issuance.

JWT claims (all mandatory):
  sub        = agent_id
  jti        = capability_id (UUID4)
  iat        = issued-at (epoch seconds)
  exp        = expires-at (epoch seconds)
  tenant_id  = tenant UUID string
  action_digest = hex SHA-256
  executor_id   = executor identifier string
  approval_ref  = approval UUID string | null
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

from security.schemas import CapabilityToken

ALGORITHM = "EdDSA"


def issue_capability(
    agent_id: str,
    tenant_id: str,
    action_digest: str,
    executor_id: str,
    ttl_seconds: int,
    approval_ref: str | None,
    signing_key: Ed25519PrivateKey,
    key_id: str,
) -> CapabilityToken:
    """
    Issue a signed, short-lived capability JWT bound to the exact action digest,
    principal, tenant and intended executor.
    """
    now = datetime.now(timezone.utc)
    cap_id = str(uuid.uuid4())
    exp = int(now.timestamp()) + ttl_seconds
    iat = int(now.timestamp())

    payload = {
        "sub": agent_id,
        "jti": cap_id,
        "iat": iat,
        "exp": exp,
        "tenant_id": tenant_id,
        "action_digest": action_digest,
        "executor_id": executor_id,
        "approval_ref": approval_ref,
    }
    headers = {"kid": key_id}

    # python-jose accepts Ed25519PrivateKey directly when the cryptography
    # backend is installed.
    token = jwt.encode(payload, signing_key, algorithm=ALGORITHM, headers=headers)
    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc).isoformat()

    return CapabilityToken(token=token, capability_id=cap_id, expires_at=expires_at)
