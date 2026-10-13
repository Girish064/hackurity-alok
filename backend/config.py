"""
backend/config.py
Application configuration loaded from environment variables via pydantic-settings.
All secrets must come from the environment, never from source code.
"""
from __future__ import annotations

import textwrap
from functools import lru_cache

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Database ─────────────────────────────────────────────────
    database_url: str = (
        "postgresql+asyncpg://agentshield:agentshield@localhost:5432/agentshield"
    )

    # ── Redis ─────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Cryptographic keys (PEM, \n-escaped in env) ───────────────
    agentshield_signing_key_pem: str = ""
    agentshield_verifying_key_pem: str = ""
    agentshield_key_id: str = "agentshield-key-v1"

    # ── Executor ──────────────────────────────────────────────────
    agentshield_executor_id: str = "agentshield-executor-v1"

    # ── TTLs (seconds) ────────────────────────────────────────────
    capability_ttl_seconds: int = 300
    consumed_capability_ttl_seconds: int = 3900
    approval_ttl_seconds: int = 1800

    # ── Rate limiting ─────────────────────────────────────────────
    rate_limit_per_minute: int = 30

    # ── Admin authentication (static token for demo) ─────────────
    admin_secret_token: str = "change-me-in-production"

    # ── App ───────────────────────────────────────────────────────
    app_env: str = "development"
    log_level: str = "INFO"

    # ── Derived key objects (populated in model_validator) ────────
    _signing_key: Ed25519PrivateKey | None = None
    _verifying_key: Ed25519PublicKey | None = None

    @field_validator("agentshield_signing_key_pem", mode="before")
    @classmethod
    def unescape_signing_pem(cls, v: str) -> str:
        return v.replace("\\n", "\n") if v else v

    @field_validator("agentshield_verifying_key_pem", mode="before")
    @classmethod
    def unescape_verifying_pem(cls, v: str) -> str:
        return v.replace("\\n", "\n") if v else v

    @model_validator(mode="after")
    def _load_or_generate_keys(self) -> "Settings":
        from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key

        if self.agentshield_signing_key_pem:
            pem = self.agentshield_signing_key_pem.encode()
            self._signing_key = load_pem_private_key(pem, password=None)  # type: ignore[assignment]
        else:
            # Auto-generate for development — log a loud warning
            import warnings
            warnings.warn(
                "AGENTSHIELD_SIGNING_KEY_PEM not set. "
                "Generating ephemeral Ed25519 key. "
                "All capabilities issued in this session will be invalid after restart.",
                stacklevel=2,
            )
            self._signing_key = Ed25519PrivateKey.generate()
            pub = self._signing_key.public_key()
            self._verifying_key = pub
            # Persist derived verifying key so executor can check it
            self.agentshield_verifying_key_pem = pub.public_bytes(
                Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
            ).decode()
            return self

        if self.agentshield_verifying_key_pem:
            pem = self.agentshield_verifying_key_pem.encode()
            self._verifying_key = load_pem_public_key(pem)  # type: ignore[assignment]
        else:
            # Derive public key from private key
            self._verifying_key = self._signing_key.public_key()

        return self

    @property
    def signing_key(self) -> Ed25519PrivateKey:
        if self._signing_key is None:
            raise RuntimeError("Signing key not initialized")
        return self._signing_key

    @property
    def verifying_key(self) -> Ed25519PublicKey:
        if self._verifying_key is None:
            raise RuntimeError("Verifying key not initialized")
        return self._verifying_key


@lru_cache
def get_settings() -> Settings:
    """Return the cached singleton Settings instance."""
    return Settings()
