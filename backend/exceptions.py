"""
backend/exceptions.py
AgentShield exception hierarchy and FastAPI exception handlers.

Design rules:
- Every security failure raises a specific subclass of AgentShieldError.
- Handlers convert exceptions to the standard error envelope:
      { "error_code": str, "message": str, "request_id": str | null }
- On unexpected exceptions the system FAILS CLOSED (returns 500, never 2xx).
"""
from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse


# ─── Base ──────────────────────────────────────────────────────────────────


class AgentShieldError(Exception):
    """Root exception for all AgentShield domain errors."""

    error_code: str = "AGENTSHIELD_ERROR"
    http_status: int = 500

    def __init__(self, message: str, request_id: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.request_id = request_id


# ─── Authentication & Identity ─────────────────────────────────────────────


class AuthenticationError(AgentShieldError):
    """Agent identity could not be verified."""
    error_code = "AUTHENTICATION_FAILED"
    http_status = 401


class AgentNotFoundError(AgentShieldError):
    """Agent record does not exist."""
    error_code = "AGENT_NOT_FOUND"
    http_status = 401


class AgentRevokedError(AgentShieldError):
    """Agent has been revoked or is subject to the kill switch."""
    error_code = "AGENT_REVOKED"
    http_status = 403


class AgentSuspendedError(AgentShieldError):
    """Agent is temporarily suspended."""
    error_code = "AGENT_SUSPENDED"
    http_status = 403


# ─── Authorization & Policy ────────────────────────────────────────────────


class PolicyDeniedError(AgentShieldError):
    """Hard policy denial — cannot be overridden."""
    error_code = "POLICY_DENIED"
    http_status = 403


class PolicyApprovalRequiredError(AgentShieldError):
    """Action requires human approval before a capability can be issued."""
    error_code = "APPROVAL_REQUIRED"
    http_status = 202  # Accepted — awaiting approval


class RateLimitExceededError(AgentShieldError):
    """Agent exceeded the per-minute submission rate limit."""
    error_code = "RATE_LIMIT_EXCEEDED"
    http_status = 429


# ─── Capability & Executor ─────────────────────────────────────────────────


class CapabilityVerificationError(AgentShieldError):
    """Capability token failed verification (signature, expiry, claims)."""
    error_code = "CAPABILITY_INVALID"
    http_status = 403


class CapabilityExpiredError(AgentShieldError):
    """Capability token has expired."""
    error_code = "CAPABILITY_EXPIRED"
    http_status = 403


class CapabilityConsumedError(AgentShieldError):
    """Capability has already been used (replay prevention)."""
    error_code = "CAPABILITY_ALREADY_CONSUMED"
    http_status = 409


class ActionDigestMismatchError(AgentShieldError):
    """Re-computed action digest does not match the capability digest."""
    error_code = "ACTION_DIGEST_MISMATCH"
    http_status = 403


class ExecutorBindingError(AgentShieldError):
    """Capability is not bound to this executor."""
    error_code = "EXECUTOR_BINDING_MISMATCH"
    http_status = 403


# ─── Approval ──────────────────────────────────────────────────────────────


class ApprovalNotFoundError(AgentShieldError):
    """Approval request does not exist."""
    error_code = "APPROVAL_NOT_FOUND"
    http_status = 404


class ApprovalVerificationError(AgentShieldError):
    """Approval record does not match the exact action digest or approver."""
    error_code = "APPROVAL_VERIFICATION_FAILED"
    http_status = 403


class ApprovalExpiredError(AgentShieldError):
    """Approval request has expired."""
    error_code = "APPROVAL_EXPIRED"
    http_status = 403


class ApprovalAlreadyDecidedError(AgentShieldError):
    """Approval request has already been decided."""
    error_code = "APPROVAL_ALREADY_DECIDED"
    http_status = 409


# ─── Security module ───────────────────────────────────────────────────────


class SecurityModuleError(AgentShieldError):
    """An unexpected error from the security module — fail closed."""
    error_code = "SECURITY_MODULE_ERROR"
    http_status = 500


# ─── Storage ───────────────────────────────────────────────────────────────


class StorageError(AgentShieldError):
    """A database or Redis operation failed — fail closed."""
    error_code = "STORAGE_ERROR"
    http_status = 500


class DuplicateRequestError(AgentShieldError):
    """Idempotent: exact same request_id was already processed."""
    error_code = "DUPLICATE_REQUEST"
    http_status = 409


# ─── FastAPI exception handlers ────────────────────────────────────────────


def _error_response(
    error_code: str,
    message: str,
    request_id: str | None,
    status_code: int,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "error_code": error_code,
            "message": message,
            "request_id": request_id,
        },
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach domain exception handlers to the FastAPI application."""

    @app.exception_handler(AgentShieldError)
    async def handle_agentshield_error(
        request: Request, exc: AgentShieldError
    ) -> JSONResponse:
        return _error_response(
            error_code=exc.error_code,
            message=exc.message,
            request_id=exc.request_id,
            status_code=exc.http_status,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(
        request: Request, exc: Exception
    ) -> JSONResponse:
        # Fail closed — never return 2xx on unexpected errors.
        import logging
        logging.getLogger("agentshield").exception(
            "Unexpected error: %s", exc, exc_info=exc
        )
        return _error_response(
            error_code="INTERNAL_ERROR",
            message="An unexpected error occurred. The request has been rejected.",
            request_id=None,
            status_code=500,
        )
