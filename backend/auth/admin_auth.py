"""
backend/auth/admin_auth.py
Admin authentication for the human approval workflow and agent management.

For the demo: a static secret token in the Authorization header.
In production, replace with a proper identity provider.
"""
from __future__ import annotations

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.config import Settings, get_settings
from backend.exceptions import AuthenticationError

_bearer = HTTPBearer(auto_error=False)


def get_admin_identity(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    settings: Settings = Depends(get_settings),
) -> str:
    """
    FastAPI dependency for admin-only endpoints.
    Returns the admin identity string (token value) on success.
    Raises AuthenticationError on failure.
    """
    if credentials is None or not credentials.credentials:
        raise AuthenticationError(
            "Missing Authorization header for admin endpoint."
        )
    token = credentials.credentials
    if token != settings.admin_secret_token:
        raise AuthenticationError("Invalid admin token.")
    # In a real system this would decode a JWT and return the admin's identity.
    return f"admin:{token[:8]}..."
