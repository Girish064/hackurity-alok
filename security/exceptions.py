"""
security/exceptions.py
Exception hierarchy for the security module.

All security errors inherit from AgentShieldSecurityError so the backend
can catch them uniformly and convert them to the appropriate HTTP response.
"""


class AgentShieldSecurityError(Exception):
    """Root exception for all security-module errors."""


class CanonicalizationError(AgentShieldSecurityError):
    """Action could not be canonicalized (e.g. invalid parameters)."""


class CapabilityVerificationError(AgentShieldSecurityError):
    """Capability token failed verification."""


class CapabilityExpiredError(CapabilityVerificationError):
    """Capability token has expired."""


class ApprovalVerificationError(AgentShieldSecurityError):
    """Approval record does not match the required action digest or approver."""


class ReceiptVerificationError(AgentShieldSecurityError):
    """Execution receipt failed verification."""


class AuditChainError(AgentShieldSecurityError):
    """Audit chain operation failed."""
