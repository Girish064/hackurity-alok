"""security/adapters.py
Backward-compatibility adapter layer bridging baseline AgentShield interfaces
with Girish's production cryptographic trust modules.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping, Optional, Sequence, Union

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# Import Girish's modules
from security import (
    action_digest as _girish_digest,
    canonicalization as _girish_canon,
    capability as _girish_cap,
    approval_binding as _girish_approval,
    execution_receipt as _girish_receipt,
    audit_chain as _girish_audit,
    key_management as _girish_key,
)
from security.exceptions import (
    AgentShieldSecurityError,
    CanonicalizationError,
    CapabilityExpiredError,
    CapabilityVerificationError,
    ApprovalVerificationError,
    ReceiptVerificationError,
    AuditChainError,
)
from security.schemas import (
    ActionRequest as BaselineActionRequest,
    CapabilityClaims as BaselineCapabilityClaims,
    CapabilityToken as BaselineCapabilityToken,
    ApprovalRecord as BaselineApprovalRecord,
    AuditRecord as BaselineAuditRecord,
    AuditChainVerificationResult,
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * ((4 - len(data) % 4) % 4)
    return base64.urlsafe_b64decode((data + padding).encode("ascii"))


# ── Canonicalization & Digest Adapters ───────────────────────────────────────

def canonicalize_action(
    action: Union[BaselineActionRequest, Mapping[str, Any], _girish_canon.CanonicalAction, str, bytes, bytearray],
) -> bytes:
    """Canonicalize action supporting both baseline ActionRequest and Schema v1."""
    if isinstance(action, BaselineActionRequest):
        sorted_params = json.dumps(
            action.parameters,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        body = (
            f'{{"action_type":"{action.action_type}",'
            f'"agent_id":"{action.agent_id}",'
            f'"parameters":{sorted_params},'
            f'"request_id":"{action.request_id}",'
            f'"submitted_at":"{action.submitted_at}",'
            f'"tenant_id":"{action.tenant_id}"}}'
        )
        return b"agentshield-action-v1:" + body.encode("utf-8")

    if isinstance(action, Mapping) and "action_type" in action and "schema_version" not in action:
        # Legacy action mapping
        params = action.get("parameters", {})
        sorted_params = json.dumps(
            params,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        body = (
            f'{{"action_type":"{action.get("action_type")}",'
            f'"agent_id":"{action.get("agent_id")}",'
            f'"parameters":{sorted_params},'
            f'"request_id":"{action.get("request_id")}",'
            f'"submitted_at":"{action.get("submitted_at")}",'
            f'"tenant_id":"{action.get("tenant_id")}"}}'
        )
        return b"agentshield-action-v1:" + body.encode("utf-8")

    return _girish_canon.canonicalize_action(action)


def calculate_action_digest(
    action: Union[BaselineActionRequest, Mapping[str, Any], _girish_canon.CanonicalAction, str, bytes, bytearray],
) -> str:
    """Calculate action digest with backward compatibility for legacy prefix."""
    if isinstance(action, (bytes, bytearray)):
        b = bytes(action)
        if b.startswith(b"agentshield-action-v1:"):
            return hashlib.sha256(b).hexdigest()

    if isinstance(action, BaselineActionRequest):
        canonical = canonicalize_action(action)
        return hashlib.sha256(canonical).hexdigest()

    return _girish_digest.calculate_action_digest(action)


# ── Capability Issuance & Verification Adapters ──────────────────────────────

def issue_capability(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface capability issuer.

    Baseline call:
      issue_capability(agent_id, tenant_id, action_digest, executor_id,
                       ttl_seconds=300, approval_ref=None, signing_key=..., key_id="key-v1")
      -> BaselineCapabilityToken

    Girish call:
      issue_capability(claims, signing_key, ttl_seconds=60)
      -> str (compact JWS)
    """
    if "agent_id" in kwargs or (len(args) >= 4 and isinstance(args[0], str) and isinstance(args[1], str)):
        agent_id = kwargs.get("agent_id") if "agent_id" in kwargs else args[0]
        tenant_id = kwargs.get("tenant_id") if "tenant_id" in kwargs else args[1]
        action_digest = kwargs.get("action_digest") if "action_digest" in kwargs else args[2]
        executor_id = kwargs.get("executor_id") if "executor_id" in kwargs else args[3]
        ttl_seconds = kwargs.get("ttl_seconds", 300)
        approval_ref = kwargs.get("approval_ref", None)
        signing_key = kwargs.get("signing_key") if "signing_key" in kwargs else (args[6] if len(args) > 6 else None)
        key_id = kwargs.get("key_id", "key-v1")

        cap_id = str(uuid.uuid4())
        now = int(time.time())
        exp = now + int(ttl_seconds)

        header = {"alg": "EdDSA", "kid": key_id, "typ": "agentshield-capability+jwt"}
        payload = {
            "iss": "agentshield-gateway",
            "aud": executor_id,
            "sub": agent_id,
            "principal_id": agent_id,
            "tenant_id": tenant_id,
            "action_digest": action_digest,
            "tool": "legacy_tool",
            "resource": "legacy_resource",
            "jti": cap_id,
            "iat": now,
            "exp": exp,
            "policy_version": 1,
            "environment": "demo",
            "intent_id": f"intent-{cap_id}",
            "kid": key_id,
            "approval_id": approval_ref,
            "schema_version": 1,
        }

        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        # Resolve Ed25519 private key
        priv = signing_key
        if isinstance(priv, str):
            priv = serialization.load_pem_private_key(priv.encode("utf-8"), password=None)
        elif isinstance(priv, _girish_key.ManagedKey):
            priv = priv.private_key

        sig_bytes = priv.sign(signing_input)
        sig_b64 = _b64url_encode(sig_bytes)
        token = f"{header_b64}.{payload_b64}.{sig_b64}"

        expires_at_iso = datetime.fromtimestamp(exp, timezone.utc).isoformat()
        return BaselineCapabilityToken(
            token=token,
            capability_id=cap_id,
            expires_at=expires_at_iso,
        )

    # Girish call
    return _girish_cap.issue_capability(*args, **kwargs)


def verify_capability(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface capability verifier.

    Baseline call:
      verify_capability(token, expected_agent_id, expected_tenant_id,
                        expected_action_digest, expected_executor_id, verifying_key)
      -> BaselineCapabilityClaims

    Girish call:
      verify_capability(signed_capability, expected_action, authenticated_principal, verification_context)
      -> VerifiedCapabilityClaims
    """
    if "token" in kwargs or "verifying_key" in kwargs or (len(args) >= 6 and isinstance(args[0], str)):
        token = kwargs.get("token") if "token" in kwargs else args[0]
        expected_agent_id = kwargs.get("expected_agent_id") if "expected_agent_id" in kwargs else args[1]
        expected_tenant_id = kwargs.get("expected_tenant_id") if "expected_tenant_id" in kwargs else args[2]
        expected_action_digest = kwargs.get("expected_action_digest") if "expected_action_digest" in kwargs else args[3]
        expected_executor_id = kwargs.get("expected_executor_id") if "expected_executor_id" in kwargs else args[4]
        verifying_key = kwargs.get("verifying_key") if "verifying_key" in kwargs else args[5]

        parts = token.split(".")
        if len(parts) != 3:
            raise CapabilityVerificationError("Invalid compact token format.")

        header_b64, payload_b64, sig_b64 = parts
        try:
            payload = json.loads(_b64url_decode(payload_b64))
            sig_bytes = _b64url_decode(sig_b64)
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        except Exception as exc:
            raise CapabilityVerificationError(f"Malformed capability token: {exc}") from exc

        pub = verifying_key
        if isinstance(pub, str):
            pub = serialization.load_pem_public_key(pub.encode("utf-8"))
        elif isinstance(pub, _girish_key.ManagedKey):
            pub = pub.public_key
        elif hasattr(pub, "public_key") and callable(pub.public_key):
            pub = pub.public_key()

        try:
            pub.verify(sig_bytes, signing_input)
        except Exception as exc:
            raise CapabilityVerificationError(f"Ed25519 signature verification failed: {exc}") from exc

        now = int(time.time())
        exp = payload.get("exp", 0)
        if exp < now:
            raise CapabilityExpiredError(f"Capability expired at {exp}, current time is {now}.")

        cap_agent = payload.get("principal_id") or payload.get("sub", "")
        cap_tenant = payload.get("tenant_id", "")
        cap_digest = payload.get("action_digest", "")
        cap_aud = payload.get("aud", "")

        if cap_agent != expected_agent_id:
            raise CapabilityVerificationError(f"Principal mismatch: {cap_agent} != {expected_agent_id}")
        if cap_tenant != expected_tenant_id:
            raise CapabilityVerificationError(f"Tenant mismatch: {cap_tenant} != {expected_tenant_id}")
        if not hmac.compare_digest(cap_digest, expected_action_digest):
            raise CapabilityVerificationError(f"Action digest mismatch: {cap_digest} != {expected_action_digest}")
        if cap_aud != expected_executor_id:
            raise CapabilityVerificationError(f"Executor mismatch: {cap_aud} != {expected_executor_id}")

        return BaselineCapabilityClaims(
            capability_id=payload.get("jti", ""),
            agent_id=cap_agent,
            tenant_id=cap_tenant,
            action_digest=cap_digest,
            executor_id=cap_aud,
            expires_at=datetime.fromtimestamp(exp, timezone.utc),
            approval_ref=payload.get("approval_id"),
            issued_at=datetime.fromtimestamp(payload.get("iat", now), timezone.utc),
        )

    # Girish call
    return _girish_cap.verify_capability(*args, **kwargs)


# ── Execution Receipt Adapters ───────────────────────────────────────────────

@_girish_cap.dataclass
class BaselineReceiptClaims:
    capability_id: str
    action_digest: str
    executor_id: str
    outcome: str
    outcome_data: dict[str, Any]
    executed_at: str


def sign_execution_receipt(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface receipt signer."""
    if "capability_id" in kwargs or (len(args) >= 6 and isinstance(args[0], str)):
        capability_id = kwargs.get("capability_id") if "capability_id" in kwargs else args[0]
        action_digest = kwargs.get("action_digest") if "action_digest" in kwargs else args[1]
        executor_id = kwargs.get("executor_id") if "executor_id" in kwargs else args[2]
        outcome = kwargs.get("outcome") if "outcome" in kwargs else args[3]
        outcome_data = kwargs.get("outcome_data") if "outcome_data" in kwargs else args[4]
        executed_at = kwargs.get("executed_at") if "executed_at" in kwargs else args[5]
        signing_key = kwargs.get("signing_key") if "signing_key" in kwargs else (args[6] if len(args) > 6 else None)
        key_id = kwargs.get("key_id", "key-v1")

        header = {"alg": "EdDSA", "kid": key_id, "typ": "agentshield-receipt+jwt"}
        payload = {
            "iss": executor_id,
            "capability_id": capability_id,
            "action_digest": action_digest,
            "executor_id": executor_id,
            "outcome": outcome,
            "outcome_data": outcome_data,
            "executed_at": executed_at,
        }

        header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        priv = signing_key
        if isinstance(priv, str):
            priv = serialization.load_pem_private_key(priv.encode("utf-8"), password=None)
        elif isinstance(priv, _girish_key.ManagedKey):
            priv = priv.private_key

        sig_bytes = priv.sign(signing_input)
        return f"{header_b64}.{payload_b64}.{_b64url_encode(sig_bytes)}"

    return _girish_receipt.sign_execution_receipt(*args, **kwargs)


def verify_execution_receipt(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface receipt verifier."""
    if len(args) == 2 and isinstance(args[0], str):
        token, verifying_key = args[0], args[1]
        parts = token.split(".")
        if len(parts) != 3:
            raise ReceiptVerificationError("Invalid receipt token format.")

        header_b64, payload_b64, sig_b64 = parts
        try:
            payload = json.loads(_b64url_decode(payload_b64))
            sig_bytes = _b64url_decode(sig_b64)
            signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
        except Exception as exc:
            raise ReceiptVerificationError(f"Malformed receipt token: {exc}") from exc

        pub = verifying_key
        if isinstance(pub, str):
            pub = serialization.load_pem_public_key(pub.encode("utf-8"))
        elif isinstance(pub, _girish_key.ManagedKey):
            pub = pub.public_key
        elif hasattr(pub, "public_key") and callable(pub.public_key):
            pub = pub.public_key()

        try:
            pub.verify(sig_bytes, signing_input)
        except Exception as exc:
            raise ReceiptVerificationError(f"Receipt Ed25519 signature invalid: {exc}") from exc

        return BaselineReceiptClaims(
            capability_id=payload.get("capability_id", ""),
            action_digest=payload.get("action_digest", ""),
            executor_id=payload.get("executor_id", ""),
            outcome=payload.get("outcome", ""),
            outcome_data=payload.get("outcome_data", {}),
            executed_at=payload.get("executed_at", ""),
        )

    return _girish_receipt.verify_execution_receipt(*args, **kwargs)


# ── Approval Binding Adapters ────────────────────────────────────────────────

def compute_approval_hmac(approval_id: str, action_digest: str, secret: str) -> str:
    """Compute HMAC-SHA256 for approval DB integrity."""
    msg = f"{approval_id}:{action_digest}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_approval(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface approval verifier."""
    if "hmac_secret" in kwargs or (len(args) >= 3 and isinstance(args[2], str)):
        approval = kwargs.get("approval") or kwargs.get("approval_record") or (args[0] if len(args) > 0 else None)
        expected_digest = (
            kwargs.get("expected_action_digest")
            or kwargs.get("action_digest")
            or (args[1] if len(args) > 1 else "")
        )
        secret = kwargs.get("hmac_secret") if "hmac_secret" in kwargs else (args[2] if len(args) > 2 else "")

        if not hmac.compare_digest(approval.action_digest, expected_digest):
            raise ApprovalVerificationError("Approval action_digest mismatch.")

        expected_hmac = compute_approval_hmac(approval.approval_id, approval.action_digest, secret)
        if not hmac.compare_digest(approval.action_hmac, expected_hmac):
            raise ApprovalVerificationError("Approval HMAC integrity check failed.")

        if approval.status != "approved":
            raise ApprovalVerificationError(f"Approval status is not approved: {approval.status}")

        return None

    return _girish_approval.verify_approval(*args, **kwargs)


# ── Audit Chain Adapters ─────────────────────────────────────────────────────

def append_audit_record(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface audit record appender."""
    if "event_type" in kwargs or (len(args) >= 4 and isinstance(args[0], str)):
        event_type = kwargs.get("event_type") if "event_type" in kwargs else args[0]
        event_data = kwargs.get("event_data") if "event_data" in kwargs else args[1]
        actor_id = kwargs.get("actor_id") if "actor_id" in kwargs else args[2]
        prev_chain_hash = kwargs.get("prev_chain_hash") if "prev_chain_hash" in kwargs else args[3]

        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        raw_bytes = json.dumps(
            {
                "actor_id": actor_id,
                "event_data": event_data,
                "event_id": event_id,
                "event_type": event_type,
                "timestamp": now,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        hasher = hashlib.sha256()
        if prev_chain_hash:
            hasher.update(prev_chain_hash.encode("ascii"))
        hasher.update(raw_bytes)
        chain_hash = hasher.hexdigest()

        return BaselineAuditRecord(
            event_id=event_id,
            event_type=event_type,
            event_data=event_data,
            actor_id=actor_id,
            timestamp=now,
            prev_chain_hash=prev_chain_hash,
            chain_hash=chain_hash,
        )

    return _girish_audit.append_audit_record(*args, **kwargs)


def verify_audit_chain(*args: Any, **kwargs: Any) -> Any:
    """Dual-interface audit chain verifier."""
    if args and isinstance(args[0], Sequence) and args[0] and isinstance(args[0][0], BaselineAuditRecord):
        records = args[0]
        prev_hash = None
        for idx, rec in enumerate(records):
            if rec.prev_chain_hash != prev_hash:
                return AuditChainVerificationResult(
                    valid=False,
                    verified_count=idx,
                    first_broken_index=idx,
                    error_message=f"prev_chain_hash mismatch at index {idx}",
                )

            raw_bytes = json.dumps(
                {
                    "actor_id": rec.actor_id,
                    "event_data": rec.event_data,
                    "event_id": rec.event_id,
                    "event_type": rec.event_type,
                    "timestamp": rec.timestamp,
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")

            hasher = hashlib.sha256()
            if prev_hash:
                hasher.update(prev_hash.encode("ascii"))
            hasher.update(raw_bytes)
            computed_hash = hasher.hexdigest()

            if computed_hash != rec.chain_hash:
                return AuditChainVerificationResult(
                    valid=False,
                    verified_count=idx,
                    first_broken_index=idx,
                    error_message=f"chain_hash mismatch at index {idx}",
                )
            prev_hash = rec.chain_hash

        return AuditChainVerificationResult(
            valid=True,
            verified_count=len(records),
            first_broken_index=None,
            error_message=None,
        )

    return _girish_audit.verify_audit_chain(*args, **kwargs)
