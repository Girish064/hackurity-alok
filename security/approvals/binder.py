"""
security/approvals/binder.py
Approval verification — ensures an approval record is bound to the exact action.

The backend (Alok) fetches the ApprovalRecord from PostgreSQL and passes it here.
This module verifies that:
  1. The approval status is "approved".
  2. The approval has not expired.
  3. The stored action_digest matches the digest of the action being executed.
  4. The HMAC integrity check passes (prevents DB tampering).

ASSUMPTION (from implementation plan):
  DB-level integrity via HMAC(approval_id ‖ action_digest) is sufficient for
  the demo. Girish may later add an approver Ed25519 signature field.
"""
from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timezone

from security.exceptions import ApprovalVerificationError
from security.schemas import ApprovalRecord

# HMAC key is derived from the admin secret — injected at call time.
# This prevents the HMAC from being useful without the key.


def compute_approval_hmac(
    approval_id: str,
    action_digest: str,
    hmac_secret: str,
) -> str:
    """
    Compute HMAC-SHA256 over (approval_id ‖ action_digest) using hmac_secret.
    Returns lowercase hex digest.
    """
    msg = f"{approval_id}:{action_digest}".encode("utf-8")
    return hmac.new(hmac_secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_approval(
    approval_record: ApprovalRecord,
    action_digest: str,
    approved_by: str,
    hmac_secret: str,
) -> None:
    """
    Verify the approval record against the exact action digest.
    Raises ApprovalVerificationError on any failure.

    Parameters
    ----------
    approval_record : ApprovalRecord
        Record fetched from PostgreSQL by Alok's backend.
    action_digest : str
        The SHA-256 hex digest of the canonical action being executed.
    approved_by : str
        The identity of the approver (must match decided_by in the record).
    hmac_secret : str
        The shared HMAC secret (e.g. ADMIN_SECRET_TOKEN).
    """
    # 1. Status must be "approved"
    if approval_record.status != "approved":
        raise ApprovalVerificationError(
            f"Approval is not in approved state: status={approval_record.status!r}"
        )

    # 2. Expiry check
    expires_at = datetime.fromisoformat(approval_record.expires_at)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > expires_at:
        raise ApprovalVerificationError("Approval has expired.")

    # 3. Digest binding — this approval must authorize this exact action
    if approval_record.action_digest != action_digest:
        raise ApprovalVerificationError(
            "Approval action_digest does not match the submitted action digest. "
            "This approval cannot authorize a different action."
        )

    # 4. HMAC integrity check
    expected_hmac = compute_approval_hmac(
        approval_record.approval_id,
        approval_record.action_digest,
        hmac_secret,
    )
    if not hmac.compare_digest(expected_hmac, approval_record.action_hmac):
        raise ApprovalVerificationError(
            "Approval HMAC integrity check failed. Record may have been tampered."
        )

    # 5. Approver identity (informational — the approver is the admin)
    if approval_record.decided_by != approved_by:
        raise ApprovalVerificationError(
            f"Approver mismatch: record says {approval_record.decided_by!r}, "
            f"but caller claims {approved_by!r}."
        )
