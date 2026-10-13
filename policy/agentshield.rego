# AgentShield — OPA Policy
# Owner: Pavan (policy design)
# Source: reva cyber hack-pavan/agentshield/policy/agentshield.rego (verbatim)
package agentshield.authz

# ============================================================
# AgentShield V2 — Default-Deny Authorization Policy
# Owner: Pavan (policy design) | Alok (OPA integration)
# Version: 3
# ============================================================

# Default: deny everything.
default allow = false
default needs_approval = false
default deny_reason = "DEFAULT_DENY"

# ─────────────────────────────────────────────────────────────
# Section 1: Hard Deny Rules (cannot be overridden by approval)
# ─────────────────────────────────────────────────────────────

# Deny actions from unregistered agents
hard_deny[reason] {
    not input.agent.registered
    reason := "AGENT_NOT_REGISTERED"
}

# Deny actions from revoked agents
hard_deny[reason] {
    input.agent.revoked == true
    reason := "AGENT_REVOKED"
}

# Deny cross-tenant resource access
hard_deny[reason] {
    input.action.tenant_id != input.agent.tenant_id
    reason := "CROSS_TENANT_ACCESS"
}

# Deny unknown tools
hard_deny[reason] {
    not input.action.tool in input.agent.permitted_tools
    reason := "TOOL_NOT_PERMITTED"
}

# Deny unknown or invalid environments
hard_deny[reason] {
    not input.action.environment in {"demo", "staging", "production"}
    reason := "INVALID_ENVIRONMENT"
}

# Deny stale policy versions (minimum acceptable version = 2)
hard_deny[reason] {
    input.action.policy_version < 2
    reason := "POLICY_VERSION_STALE"
}

# Deny refunds above the hard maximum (no approval can override)
hard_deny[reason] {
    input.action.tool == "issue_refund"
    input.action.arguments.amount_minor > 1000000
    reason := "AMOUNT_EXCEEDS_HARD_MAXIMUM"
}

# ─────────────────────────────────────────────────────────────
# Section 2: Needs Approval Rules
# (blocked until human approval is recorded and verified)
# ─────────────────────────────────────────────────────────────

# Refunds between 30000 and 1000000 paise require approval
needs_approval {
    count(hard_deny) == 0
    input.action.tool == "issue_refund"
    input.action.arguments.amount_minor >= 30000
    input.action.arguments.amount_minor <= 1000000
}

# ─────────────────────────────────────────────────────────────
# Section 3: Allow Rules
# (all hard_deny checks must pass; needs_approval handled separately)
# ─────────────────────────────────────────────────────────────

# Allow small refunds without approval
allow {
    count(hard_deny) == 0
    not needs_approval
    input.action.tool == "issue_refund"
    input.action.arguments.amount_minor > 0
    input.action.arguments.amount_minor < 30000
    resource_owned_by_tenant
}

# Allow refunds that have valid approval already recorded
allow {
    count(hard_deny) == 0
    needs_approval
    input.approval.valid == true
    input.approval.action_digest == input.action.action_digest
    input.approval.tenant_id == input.action.tenant_id
    input.approval.consumed == false
    input.approval.decision == "approved"
    resource_owned_by_tenant
}

# ─────────────────────────────────────────────────────────────
# Section 4: Helper Rules
# ─────────────────────────────────────────────────────────────

resource_owned_by_tenant {
    # The gateway verifies resource ownership via database lookup.
    # This helper is a policy-level check using data passed in input.
    input.resource.owner_tenant_id == input.action.tenant_id
}

# ─────────────────────────────────────────────────────────────
# Section 5: Decision Output
# ─────────────────────────────────────────────────────────────

# Final decision object returned to the gateway / executor
decision = result {
    count(hard_deny) > 0
    result := {
        "result": "deny",
        "reason": concat(", ", hard_deny)
    }
} else = result {
    needs_approval
    not allow
    result := {
        "result": "needs_approval",
        "approval_type": "manager_approval",
        "reason": "APPROVAL_REQUIRED_FOR_AMOUNT"
    }
} else = result {
    allow
    result := {
        "result": "allow",
        "reason": "POLICY_ALLOW"
    }
} else = result {
    result := {
        "result": "deny",
        "reason": "DEFAULT_DENY"
    }
}
