"""Key Management & Planned Rotation for AgentShield V2.

Manages Ed25519 signing and verification keys with explicit key IDs (kid),
purpose separation (capability, approval, receipt, audit), lifecycle status
(ACTIVE, RETIRED, REVOKED), and historical verification rules.

Security invariants:
- Private keys are never included in __repr__, __str__, logs, or exported metadata.
- Unknown or revoked keys are always rejected.
- Capabilities require an ACTIVE key (or RETIRED key only if issued prior to retirement
  and still within its short-lived expiry window).
- Receipts and audit records support historical verification with RETIRED keys
  provided the record timestamp precedes the key's retirement timestamp.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


class KeyPurpose(str, Enum):
    """Designated cryptographic purpose for an Ed25519 key."""

    CAPABILITY = "capability"
    APPROVAL = "approval"
    RECEIPT = "receipt"
    AUDIT = "audit"
    ALL = "all"


class KeyStatus(str, Enum):
    """Lifecycle state of a managed cryptographic key."""

    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    REVOKED = "REVOKED"


from .exceptions import AgentShieldSecurityError


class KeyManagementError(AgentShieldSecurityError):
    """Base error for key management and key verification failures."""

    def __init__(self, message: str, error_code: str = "KEY_MANAGEMENT_ERROR") -> None:
        super().__init__(message)
        self.error_code = error_code


class UnknownKeyError(KeyManagementError):
    """Raised when a key ID (kid) is not recognized by the KeyManager."""

    def __init__(self, kid: str) -> None:
        super().__init__(f"Unknown signing key ID: {kid!r}", error_code="UNKNOWN_SIGNING_KEY")
        self.kid = kid


class RevokedKeyError(KeyManagementError):
    """Raised when a key has been revoked due to compromise or administrative action."""

    def __init__(self, kid: str) -> None:
        super().__init__(f"Signing key {kid!r} is REVOKED.", error_code="REVOKED_SIGNING_KEY")
        self.kid = kid


class RetiredKeyError(KeyManagementError):
    """Raised when a retired key is used for new issuance or outside its valid historical window."""

    def __init__(self, message: str, error_code: str = "RETIRED_SIGNING_KEY") -> None:
        super().__init__(message, error_code=error_code)


class KeyPurposeMismatchError(KeyManagementError):
    """Raised when a key is used for a purpose other than its designated scope."""

    def __init__(self, kid: str, actual: KeyPurpose, expected: KeyPurpose) -> None:
        super().__init__(
            f"Key {kid!r} has purpose {actual.value!r}, cannot be used for {expected.value!r}.",
            error_code="KEY_PURPOSE_MISMATCH",
        )


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded URL-safe Base64 ASCII string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Decode unpadded URL-safe Base64 string into bytes."""
    if not isinstance(text, str) or not text:
        raise ValueError("Invalid base64url input")
    padding = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode((text + padding).encode("ascii"))


@dataclass
class ManagedKey:
    """Represents an Ed25519 key pair or public verification key with lifecycle metadata."""

    kid: str
    purpose: KeyPurpose
    public_key: Ed25519PublicKey
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: int = field(default_factory=lambda: int(time.time()))
    retired_at: Optional[int] = None
    revoked_at: Optional[int] = None
    _private_key: Optional[Ed25519PrivateKey] = field(default=None, repr=False)

    def __repr__(self) -> str:
        return (
            f"ManagedKey(kid={self.kid!r}, purpose={self.purpose.value!r}, "
            f"status={self.status.value!r}, created_at={self.created_at}, "
            f"retired_at={self.retired_at}, has_private_key={self._private_key is not None})"
        )

    def __str__(self) -> str:
        return self.__repr__()

    @property
    def can_sign(self) -> bool:
        """Return True if this key has private material and is ACTIVE."""
        return self._private_key is not None and self.status == KeyStatus.ACTIVE

    def public_bytes_raw(self) -> bytes:
        """Return the 32-byte raw Ed25519 public key."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_jwk(self) -> dict[str, Any]:
        """Export public key metadata in JWK-compatible format (never exports private key)."""
        return {
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": self.kid,
            "use": "sig",
            "alg": "EdDSA",
            "x": b64url_encode(self.public_bytes_raw()),
            "purpose": self.purpose.value,
            "status": self.status.value,
            "created_at": self.created_at,
            "retired_at": self.retired_at,
            "revoked_at": self.revoked_at,
        }

    def sign(self, message: bytes) -> bytes:
        """Sign bytes using Ed25519. Requires an ACTIVE key with private key material."""
        if self.status == KeyStatus.REVOKED:
            raise RevokedKeyError(self.kid)
        if self.status == KeyStatus.RETIRED:
            raise RetiredKeyError(
                f"Cannot sign new artifacts with retired key {self.kid!r}.",
                error_code="RETIRED_SIGNING_KEY",
            )
        if self._private_key is None:
            raise KeyManagementError(
                f"Key {self.kid!r} is a verification-only public key and cannot sign.",
                error_code="PRIVATE_KEY_UNAVAILABLE",
            )
        return self._private_key.sign(message)

    def verify_signature(self, signature: bytes, message: bytes) -> bool:
        """Verify an Ed25519 signature over message bytes."""
        try:
            self.public_key.verify(signature, message)
            return True
        except InvalidSignature:
            return False

    @classmethod
    def generate(
        cls,
        kid: str,
        purpose: KeyPurpose = KeyPurpose.ALL,
        created_at: Optional[int] = None,
    ) -> "ManagedKey":
        """Generate a fresh random Ed25519 key pair."""
        priv = Ed25519PrivateKey.generate()
        return cls(
            kid=kid,
            purpose=purpose,
            public_key=priv.public_key(),
            status=KeyStatus.ACTIVE,
            created_at=created_at if created_at is not None else int(time.time()),
            _private_key=priv,
        )

    @classmethod
    def from_seed(
        cls,
        kid: str,
        seed_32_bytes: bytes,
        purpose: KeyPurpose = KeyPurpose.ALL,
        created_at: int = 1700000000,
    ) -> "ManagedKey":
        """Create a deterministic Ed25519 key pair from a 32-byte seed."""
        if len(seed_32_bytes) != 32:
            raise ValueError("Ed25519 private key seed must be exactly 32 bytes.")
        priv = Ed25519PrivateKey.from_private_bytes(seed_32_bytes)
        return cls(
            kid=kid,
            purpose=purpose,
            public_key=priv.public_key(),
            status=KeyStatus.ACTIVE,
            created_at=created_at,
            _private_key=priv,
        )

    def public_only(self) -> "ManagedKey":
        """Return a copy of this ManagedKey stripped of private key material (for verifiers)."""
        return ManagedKey(
            kid=self.kid,
            purpose=self.purpose,
            public_key=self.public_key,
            status=self.status,
            created_at=self.created_at,
            retired_at=self.retired_at,
            revoked_at=self.revoked_at,
            _private_key=None,
        )


class KeyManager:
    """Registry of trusted Ed25519 keys supporting rotation, retirement, and revocation."""

    def __init__(self, keys: Optional[list[ManagedKey]] = None) -> None:
        self._keys: dict[str, ManagedKey] = {}
        if keys:
            for k in keys:
                self.register_key(k)

    def register_key(self, key: ManagedKey) -> None:
        """Register a ManagedKey in the manager."""
        if not key.kid or not isinstance(key.kid, str):
            raise KeyManagementError("Key ID (kid) must be a non-empty string.")
        self._keys[key.kid] = key

    def get_key(self, kid: str) -> ManagedKey:
        """Return a ManagedKey by kid or raise UnknownKeyError."""
        if kid not in self._keys:
            raise UnknownKeyError(kid)
        return self._keys[kid]

    def get_signing_key(
        self,
        kid: Optional[str] = None,
        purpose: KeyPurpose = KeyPurpose.ALL,
    ) -> ManagedKey:
        """Retrieve an ACTIVE signing key for the requested purpose."""
        if kid is not None:
            key = self.get_key(kid)
            if key.status == KeyStatus.REVOKED:
                raise RevokedKeyError(key.kid)
            if key.status == KeyStatus.RETIRED:
                raise RetiredKeyError(f"Key {key.kid!r} is retired and cannot sign new data.")
            if purpose != KeyPurpose.ALL and key.purpose not in {purpose, KeyPurpose.ALL}:
                raise KeyPurposeMismatchError(key.kid, key.purpose, purpose)
            if not key.can_sign:
                raise KeyManagementError(
                    f"Key {key.kid!r} has no private signing key material.",
                    error_code="PRIVATE_KEY_UNAVAILABLE",
                )
            return key

        # Find the newest active signing key matching purpose
        candidates = [
            k
            for k in self._keys.values()
            if k.can_sign and (k.purpose == purpose or k.purpose == KeyPurpose.ALL)
        ]
        if not candidates:
            raise KeyManagementError(
                f"No active signing key available for purpose {purpose.value!r}.",
                error_code="NO_ACTIVE_SIGNING_KEY",
            )
        # Prefer exact purpose match over KeyPurpose.ALL, then newest created_at
        candidates.sort(key=lambda k: (k.purpose == purpose, k.created_at), reverse=True)
        return candidates[0]

    def get_verification_key(
        self,
        kid: str,
        purpose: KeyPurpose,
        *,
        record_timestamp: Optional[int] = None,
        allow_retired: bool = False,
        clock_skew_seconds: int = 5,
    ) -> ManagedKey:
        """Retrieve and validate a key for signature verification under the historical policy."""
        key = self.get_key(kid)

        if key.status == KeyStatus.REVOKED:
            raise RevokedKeyError(kid)

        if purpose != KeyPurpose.ALL and key.purpose not in {purpose, KeyPurpose.ALL}:
            raise KeyPurposeMismatchError(kid, key.purpose, purpose)

        if record_timestamp is not None and record_timestamp < (key.created_at - clock_skew_seconds):
            raise KeyManagementError(
                f"Artifact timestamp ({record_timestamp}) predates creation of key {kid!r} ({key.created_at}).",
                error_code="TIMESTAMP_BEFORE_KEY_CREATION",
            )

        if key.status == KeyStatus.RETIRED:
            if not allow_retired:
                raise RetiredKeyError(
                    f"Key {kid!r} is RETIRED and not accepted for this verification context.",
                    error_code="RETIRED_SIGNING_KEY",
                )
            if key.retired_at is None or record_timestamp is None:
                raise RetiredKeyError(
                    f"Key {kid!r} is RETIRED and historical timestamp context is missing.",
                    error_code="RETIRED_KEY_MISSING_TIMESTAMP",
                )
            if record_timestamp > key.retired_at + clock_skew_seconds:
                raise RetiredKeyError(
                    f"Artifact timestamp ({record_timestamp}) is after retirement of key {kid!r} ({key.retired_at}).",
                    error_code="KEY_USED_AFTER_RETIREMENT",
                )

        return key

    def retire_key(self, kid: str, retired_at: Optional[int] = None) -> ManagedKey:
        """Transition an ACTIVE key to RETIRED status."""
        key = self.get_key(kid)
        if key.status == KeyStatus.REVOKED:
            raise RevokedKeyError(kid)
        key.status = KeyStatus.RETIRED
        key.retired_at = retired_at if retired_at is not None else int(time.time())
        return key

    def revoke_key(self, kid: str, revoked_at: Optional[int] = None) -> ManagedKey:
        """Transition a key to REVOKED status (immediate invalidation)."""
        key = self.get_key(kid)
        key.status = KeyStatus.REVOKED
        key.revoked_at = revoked_at if revoked_at is not None else int(time.time())
        return key

    def rotate_key(
        self,
        old_kid: str,
        new_kid: str,
        *,
        retired_at: Optional[int] = None,
        new_seed: Optional[bytes] = None,
    ) -> ManagedKey:
        """Retire old_kid and register a new ACTIVE key with the same purpose."""
        old_key = self.get_key(old_kid)
        ts = retired_at if retired_at is not None else int(time.time())
        self.retire_key(old_kid, retired_at=ts)

        if new_seed is not None:
            new_key = ManagedKey.from_seed(
                kid=new_kid,
                seed_32_bytes=new_seed,
                purpose=old_key.purpose,
                created_at=ts,
            )
        else:
            new_key = ManagedKey.generate(
                kid=new_kid,
                purpose=old_key.purpose,
                created_at=ts,
            )
        self.register_key(new_key)
        return new_key

    def public_verifier_store(self) -> "KeyManager":
        """Return a KeyManager containing only public verification keys (safe for verifiers)."""
        return KeyManager([k.public_only() for k in self._keys.values()])

    def export_public_jwks(self) -> dict[str, Any]:
        """Export all registered public keys as a JWK Set."""
        return {"keys": [k.public_jwk() for k in self._keys.values()]}


def _derive_seed_from_secret(master_secret: str, label: str) -> bytes:
    """Derive a deterministic 32-byte Ed25519 seed from an environment secret and purpose label."""
    return hashlib.sha256(f"AGENTSHIELD-KEY-DERIVE-V1:{label}:{master_secret}".encode("utf-8")).digest()


def create_default_key_manager(
    env_secret: Optional[str] = None,
    created_at: int = 1700000000,
) -> KeyManager:
    """Create a KeyManager with separate keys for capabilities, approvals, receipts, and audit records.

    Uses AGENTSHIELD_KEY_SEED from the environment if present, or a deterministic demo seed
    for reproducible local testing when AGENTSHIELD_ENV is demo/test.
    """
    secret = env_secret or os.environ.get("AGENTSHIELD_KEY_SEED", "agentshield-demo-ephemeral-seed-v2")
    if os.environ.get("AGENTSHIELD_ENV") == "production" and not env_secret and "AGENTSHIELD_KEY_SEED" not in os.environ:
        raise KeyManagementError(
            "AGENTSHIELD_KEY_SEED must be explicitly set in production environment.",
            error_code="MISSING_PRODUCTION_KEY_SEED",
        )

    keys = [
        ManagedKey.from_seed(
            kid="key-cap-2026-01",
            seed_32_bytes=_derive_seed_from_secret(secret, "capability-v1"),
            purpose=KeyPurpose.CAPABILITY,
            created_at=created_at,
        ),
        ManagedKey.from_seed(
            kid="key-appr-2026-01",
            seed_32_bytes=_derive_seed_from_secret(secret, "approval-v1"),
            purpose=KeyPurpose.APPROVAL,
            created_at=created_at,
        ),
        ManagedKey.from_seed(
            kid="key-rcpt-2026-01",
            seed_32_bytes=_derive_seed_from_secret(secret, "receipt-v1"),
            purpose=KeyPurpose.RECEIPT,
            created_at=created_at,
        ),
        ManagedKey.from_seed(
            kid="key-audit-2026-01",
            seed_32_bytes=_derive_seed_from_secret(secret, "audit-v1"),
            purpose=KeyPurpose.AUDIT,
            created_at=created_at,
        ),
    ]
    return KeyManager(keys)
