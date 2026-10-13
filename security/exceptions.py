# security/exceptions.py
"""Exception hierarchy for the security module.
All security errors inherit from AgentShieldSecurityError so the backend can catch them uniformly and convert them to appropriate HTTP responses.
"""
from __future__ import annotations

class AgentShieldSecurityError(Exception):
    """Root exception for all security-module errors."""

    def __init__(self, message: str = "", error_code: str = "SECURITY_MODULE_ERROR") -> None:
        super().__init__(message)
        self.error_code = error_code

# Mapping of exception names to the module that defines them.
_EXCEPTION_MODULES: dict[str, str] = {
    # canonicalization module
    "CanonicalizationError": "security.canonicalization",
    "DuplicateKeyError": "security.canonicalization",
    "SchemaValidationError": "security.canonicalization",
    # capability module
    "CapabilityVerificationError": "security.capability",
    "CapabilityExpiredError": "security.capability",
    # approval_binding module
    "ApprovalVerificationError": "security.approval_binding",
    # execution_receipt module
    "ReceiptVerificationError": "security.execution_receipt",
    # audit_chain module
    "AuditChainError": "security.audit_chain",
    # key_management module
    "KeyManagementError": "security.key_management",
    "UnknownKeyError": "security.key_management",
    "RevokedKeyError": "security.key_management",
    "RetiredKeyError": "security.key_management",
}

def __getattr__(name: str):
    """Lazily import exception classes to avoid circular imports.
    If the requested name is in _EXCEPTION_MODULES, import the defining module and return the attribute.
    Otherwise raise AttributeError.
    """
    module_path = _EXCEPTION_MODULES.get(name)
    if module_path is None:
        raise AttributeError(f"module 'security.exceptions' has no attribute {name!r}")
    module = __import__(module_path, fromlist=[name])
    return getattr(module, name)

def __dir__():
    """Return a list of available attributes for ``dir()`` support."""
    return sorted(list(globals().keys()) + list(_EXCEPTION_MODULES.keys()))

__all__ = [
    "AgentShieldSecurityError",
    "CanonicalizationError",
    "DuplicateKeyError",
    "SchemaValidationError",
    "CapabilityVerificationError",
    "CapabilityExpiredError",
    "ApprovalVerificationError",
    "ReceiptVerificationError",
    "AuditChainError",
    "KeyManagementError",
    "UnknownKeyError",
    "RevokedKeyError",
    "RetiredKeyError",
]
