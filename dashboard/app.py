"""
dashboard/app.py
AgentShield V3 — Defender Dashboard (Streamlit)

Professional cybersecurity operations console.
All data comes from the backend API — no fabricated values.

Run: streamlit run dashboard/app.py
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

import pandas as pd
import streamlit as st

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.api_client import (
    get_config,
    get_metrics,
    health,
    list_actions,
    list_audit,
    list_receipts,
    set_config,
    system_status,
    verify_audit_chain,
    verify_receipt,
)

# ── Page config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AgentShield V3 — Defender Console",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Dark theme CSS ─────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* Dark console theme */
    .stApp { background-color: #0d1117; color: #c9d1d9; }
    .block-container { padding-top: 1.5rem; padding-bottom: 1.5rem; }
    section[data-testid="stSidebar"] { background-color: #161b22; border-right: 1px solid #30363d; }
    section[data-testid="stSidebar"] * { color: #c9d1d9 !important; }
    h1, h2, h3, h4 { color: #58a6ff !important; font-family: 'JetBrains Mono', 'Consolas', monospace; }
    .metric-card {
        background: #161b22;
        border: 1px solid #30363d;
        border-radius: 6px;
        padding: 1rem 1.2rem;
        margin-bottom: 0.5rem;
    }
    .status-ok     { color: #3fb950; font-weight: 600; }
    .status-warn   { color: #d29922; font-weight: 600; }
    .status-error  { color: #f85149; font-weight: 600; }
    .status-info   { color: #58a6ff; font-weight: 600; }
    .badge-A { background:#3d1e00; color:#d29922; border-radius:4px; padding:2px 8px; font-weight:700; }
    .badge-B { background:#0d2b4e; color:#79c0ff; border-radius:4px; padding:2px 8px; font-weight:700; }
    .badge-C { background:#0d2d17; color:#3fb950; border-radius:4px; padding:2px 8px; font-weight:700; }
    .code-block { font-family: 'JetBrains Mono','Consolas',monospace; font-size:0.82rem; }
    .section-divider { border-top: 1px solid #30363d; margin: 1.2rem 0; }
    /* Table overrides */
    .stDataFrame { background-color: #161b22 !important; }
    [data-testid="stMetricValue"] { color: #58a6ff !important; font-weight: 700; font-size: 1.6rem !important; }
    [data-testid="stMetricLabel"] { color: #8b949e !important; font-size: 0.8rem !important; text-transform: uppercase; letter-spacing: 0.05em; }
</style>
""", unsafe_allow_html=True)

# ── Sidebar ────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡 AgentShield V3")
    st.markdown("**Adaptive Zero-Trust Action Security**")
    st.markdown('<hr style="border-color:#30363d">', unsafe_allow_html=True)

    page = st.radio(
        "Navigation",
        [
            "A · System Overview",
            "B · Live Action Feed",
            "C · Adaptive Trust",
            "D · Security Evidence",
            "E · Baseline Comparison",
            "F · Metrics",
            "G · Audit & Export",
        ],
        label_visibility="collapsed",
    )

    st.markdown('<hr style="border-color:#30363d">', unsafe_allow_html=True)
    api_url = st.text_input("API URL", value=os.environ.get("AGENTSHIELD_API_URL", "http://localhost:8000"))
    if api_url:
        os.environ["AGENTSHIELD_API_URL"] = api_url

    if st.button("↺  Refresh", use_container_width=True):
        st.cache_data.clear()

    st.markdown('<hr style="border-color:#30363d">', unsafe_allow_html=True)
    st.caption("Don't just detect —\nmathematically guarantee the boundary.")


# ── Helpers ────────────────────────────────────────────────────────────────

def _status_badge(s: str) -> str:
    s = str(s).lower()
    if s in ("ok", "success", "allow", "executed"):
        return f'<span class="status-ok">● {s.upper()}</span>'
    elif s in ("degraded", "warn", "require_approval", "awaiting_approval"):
        return f'<span class="status-warn">◆ {s.upper()}</span>'
    elif s in ("error", "deny", "denied", "blocked", "revoked"):
        return f'<span class="status-error">✗ {s.upper()}</span>'
    else:
        return f'<span class="status-info">· {s.upper()}</span>'

def _baseline_badge(b: str) -> str:
    return f'<span class="badge-{b}">{b}</span>'

def _empty(msg: str = "No data available yet."):
    st.markdown(f'<div style="color:#8b949e;padding:1.5rem 0;text-align:center">{msg}</div>', unsafe_allow_html=True)

@st.cache_data(ttl=10)
def _health():
    return health()

@st.cache_data(ttl=10)
def _system_status():
    return system_status()

@st.cache_data(ttl=10)
def _config():
    return get_config()

@st.cache_data(ttl=5)
def _metrics():
    return get_metrics()

@st.cache_data(ttl=5)
def _actions(limit=50):
    return list_actions(limit)

@st.cache_data(ttl=5)
def _receipts(limit=50):
    return list_receipts(limit)

@st.cache_data(ttl=10)
def _audit(limit=100):
    return list_audit(limit)


# ══════════════════════════════════════════════════════════════════════════════
# PAGE A — SYSTEM OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
if page.startswith("A"):
    st.title("System Overview")

    h_data = _health()
    s_data = _system_status()
    m_data = _metrics()
    c_data = _config()

    # ── Component health ───────────────────────────────────────────────────
    st.markdown("### Component Health")
    if h_data.get("status") == "error" and h_data.get("code") == "API_UNREACHABLE":
        st.error(f"⚠ Cannot reach API at `{api_url}`. Start the backend first.")
    else:
        components = h_data.get("data", {}).get("components", {})
        cols = st.columns(len(components) or 1)
        for i, (name, status) in enumerate(components.items()):
            with cols[i]:
                icon = "✅" if status == "ok" else ("⚠" if "disabled" in status else "❌")
                st.markdown(f"**{name.replace('_',' ').title()}**")
                st.markdown(f"{icon} `{status}`")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Active baseline ────────────────────────────────────────────────────
    st.markdown("### Active Baseline")
    active_cfg = c_data.get("data", {}).get("active_baseline", {})
    if active_cfg:
        b_id = active_cfg.get("id", "?")
        b_name = active_cfg.get("name", "Unknown")
        b_risk = active_cfg.get("risk_level", "unknown")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Baseline", f"{b_id} — {b_name}")
        with col2:
            st.metric("Risk Level", b_risk.upper())
        with col3:
            checks = active_cfg.get("checks", {})
            active_checks = sum(1 for v in checks.values() if v)
            st.metric("Active Checks", f"{active_checks}/{len(checks)}")

        checks = active_cfg.get("checks", {})
        check_cols = st.columns(len(checks))
        for i, (k, v) in enumerate(checks.items()):
            with check_cols[i]:
                icon = "✅" if v else "❌"
                st.markdown(f"{icon} `{k.replace('_',' ')}`")
    else:
        _empty("Could not retrieve baseline configuration.")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Recent activity summary ────────────────────────────────────────────
    st.markdown("### Recent Activity")
    metrics_data = m_data.get("data", {})
    subs = metrics_data.get("submissions", {})
    execs = metrics_data.get("executions", {})

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Submissions", subs.get("total", 0))
    with col2:
        st.metric("Allowed", subs.get("allowed", 0))
    with col3:
        st.metric("Blocked", subs.get("denied", 0))
    with col4:
        st.metric("Executions", execs.get("total", 0))

    # Recent 10 actions
    st.markdown("**Last 10 Actions**")
    a_data = _actions(10)
    actions = a_data.get("data", {}).get("actions", [])
    if actions:
        rows = []
        for a in actions:
            rows.append({
                "Time": a.get("submitted_at", "")[:19] if a.get("submitted_at") else "",
                "Type": a.get("action_type", ""),
                "Decision": a.get("policy_decision", ""),
                "Status": a.get("status", ""),
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        _empty("No actions yet. Submit an action via the CLI or API to see data here.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE B — LIVE ACTION FEED
# ══════════════════════════════════════════════════════════════════════════════
elif page.startswith("B"):
    st.title("Live Action Feed")

    col_filter1, col_filter2, col_filter3 = st.columns(3)
    with col_filter1:
        filter_type = st.text_input("Filter by action type", "")
    with col_filter2:
        filter_status = st.selectbox(
            "Filter by status",
            ["", "capability_issued", "executed", "denied", "awaiting_approval"],
        )
    with col_filter3:
        limit = st.number_input("Limit", min_value=5, max_value=200, value=50, step=5)

    st.cache_data.clear()
    a_data = list_actions(int(limit))
    actions = a_data.get("data", {}).get("actions", [])

    if filter_type:
        actions = [a for a in actions if filter_type.upper() in a.get("action_type", "").upper()]
    if filter_status:
        actions = [a for a in actions if a.get("status") == filter_status]

    st.markdown(f"**{len(actions)} action(s)**")

    if actions:
        rows = []
        for a in actions:
            rows.append({
                "Submitted": a.get("submitted_at", "")[:19] if a.get("submitted_at") else "—",
                "Request ID": str(a.get("request_id", ""))[:8] + "…",
                "Agent ID": str(a.get("agent_id", ""))[:8] + "…",
                "Action Type": a.get("action_type", ""),
                "Decision": a.get("policy_decision", ""),
                "Status": a.get("status", ""),
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        # Detail expander
        with st.expander("📋 View action detail"):
            req_id = st.text_input("Paste full Request ID")
            if req_id:
                from dashboard.api_client import get_action
                detail = get_action(req_id)
                if detail.get("status") == "success":
                    st.json(detail.get("data", {}))
                else:
                    st.error(detail.get("message", "Not found"))
    else:
        _empty("No actions matching the filter. Submit actions via the CLI or API.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE C — ADAPTIVE TRUST
# ══════════════════════════════════════════════════════════════════════════════
elif page.startswith("C"):
    st.title("Adaptive Trust Policy")
    st.markdown("""
    Simulate the adaptive policy engine directly. Enter context parameters and see
    the confidence score, risk classification, and policy decision in real time.
    All computation is deterministic — no AI scoring.
    """)

    with st.form("policy_eval"):
        col1, col2 = st.columns(2)
        with col1:
            role = st.selectbox(
                "Agent Role",
                ["support_agent", "finance_agent", "admin_agent", "read_only", "demo_agent", "unknown_role"],
            )
            action = st.selectbox(
                "Action Type",
                ["ISSUE_REFUND", "SEND_EMAIL", "TRANSFER_FUNDS", "EXPORT_DATA", "DELETE_RECORD", "READ_RECORD"],
            )
            scope = st.number_input("Requested Scope (amount/count)", min_value=0.0, value=500.0, step=100.0)
        with col2:
            permitted = st.multiselect(
                "Permitted Actions (agent's permission set)",
                ["ISSUE_REFUND", "SEND_EMAIL", "TRANSFER_FUNDS", "EXPORT_DATA", "DELETE_RECORD", "READ_RECORD"],
                default=["ISSUE_REFUND", "SEND_EMAIL"],
            )
            context_valid = st.checkbox("Context validation passed", value=True)
            context_reason = st.text_input("Context reason", value="Tenant isolation confirmed")
            failures = st.number_input("Recent failures", min_value=0, max_value=20, value=0)
            suspicious = st.checkbox("Suspicious activity flag", value=False)

        submitted = st.form_submit_button("Evaluate Policy", use_container_width=True)

    if submitted:
        # Import directly — this is pure computation, no backend call needed
        from core.adaptive_policy import AdaptivePolicyInput, evaluate_adaptive_policy, PolicyOutcome, RiskLevel
        inp = AdaptivePolicyInput(
            agent_id="dashboard-eval",
            agent_role=role,
            permitted_actions=permitted,
            action_type=action,
            requested_scope=scope,
            context_valid=context_valid,
            context_reason=context_reason,
            recent_failures=failures,
            suspicious_activity=suspicious,
        )
        dec = evaluate_adaptive_policy(inp)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # Confidence gauge
        conf_pct = int(dec.confidence * 100)
        risk_color = {"LOW": "#3fb950", "MEDIUM": "#d29922", "HIGH": "#f85149", "CRITICAL": "#f85149"}.get(dec.risk_level.value, "#8b949e")
        st.markdown(f"""
        <div class="metric-card">
            <div style="font-size:0.75rem;color:#8b949e;text-transform:uppercase;letter-spacing:.05em">Confidence Score</div>
            <div style="font-size:2.5rem;font-weight:700;color:{risk_color}">{dec.confidence:.4f}</div>
            <div style="background:#21262d;border-radius:4px;height:10px;margin:8px 0">
                <div style="background:{risk_color};width:{conf_pct}%;height:10px;border-radius:4px"></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Outcome", dec.outcome.value)
        with col2:
            st.metric("Risk Level", dec.risk_level.value)
        with col3:
            st.metric("Allowed Scope", f"{dec.allowed_scope}")
        with col4:
            st.metric("Capability TTL", f"{dec.capability_ttl_seconds}s")

        if dec.requires_human_approval:
            st.warning(f"⚠ **Human Approval Required:** {dec.approval_reason}")

        st.markdown("**Policy Rules Fired:**")
        for rid in dec.rule_ids:
            icon = "✅" if not any(x in rid for x in ["INVALID", "EXCEEDED", "DENY", "NOT_PERMITTED", "SUSPICIOUS", "FAILURE"]) else "❌"
            st.markdown(f"{icon} `{rid}`")

        st.markdown("**Explanation:**")
        for part in dec.explanation.split(" | "):
            st.markdown(f"- {part}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE D — SECURITY EVIDENCE
# ══════════════════════════════════════════════════════════════════════════════
elif page.startswith("D"):
    st.title("Security Evidence")

    st.markdown("### Receipt Verification")
    receipt_token = st.text_area("Paste receipt JWT token", height=80)
    if st.button("Verify Receipt"):
        if receipt_token.strip():
            result = verify_receipt(receipt_token.strip())
            if result.get("data", {}).get("valid"):
                st.success("✅ Receipt is valid and signature verified.")
                st.json(result.get("data", {}))
            else:
                st.error(f"❌ Receipt invalid: {result.get('message', 'Verification failed')}")
                st.json(result.get("data", {}))
        else:
            st.warning("Paste a receipt token first.")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    st.markdown("### Audit Chain Integrity")
    admin_token = st.text_input("Admin token (for chain verification)", type="password")
    if st.button("Verify Audit Chain"):
        if admin_token:
            result = verify_audit_chain(admin_token)
            d = result.get("data", result)
            valid = d.get("valid", False)
            if valid:
                st.success(f"✅ Audit chain valid. {d.get('verified_count', 0)} records verified.")
            else:
                st.error(f"❌ Chain integrity failure at index {d.get('first_broken_index')}. Error: {d.get('error_message')}")
            if d.get("limitation"):
                st.info(f"ℹ {d.get('limitation')}")
        else:
            st.warning("Enter admin token to verify chain.")

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    st.markdown("### Execution Receipts")
    r_data = _receipts(20)
    receipts = r_data.get("data", {}).get("receipts", [])
    if receipts:
        rows = []
        for r in receipts:
            rows.append({
                "Execution ID": str(r.get("execution_id", ""))[:12] + "…",
                "Agent ID": str(r.get("agent_id", ""))[:8] + "…",
                "Tool": r.get("tool_name", ""),
                "Outcome": r.get("outcome", ""),
                "Has Receipt": "✅" if r.get("has_receipt") else "❌",
                "Executed At": str(r.get("executed_at", ""))[:19],
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        _empty("No execution records yet.")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE E — BASELINE COMPARISON
# ══════════════════════════════════════════════════════════════════════════════
elif page.startswith("E"):
    st.title("Baseline Comparison")
    st.markdown("""
    Three baselines with different security enforcement levels.
    Each has real behavioral differences — not just labels.
    """)

    c_data = _config()
    baselines = c_data.get("data", {}).get("available_baselines", {})
    active_id = c_data.get("data", {}).get("active_baseline", {}).get("id", "C")

    if baselines:
        cols = st.columns(3)
        check_labels = {
            "policy_evaluation": "Policy Evaluation",
            "capability_issuance": "Capability Issuance",
            "check_action_digest": "Action Digest Verification",
            "verify_capability_signature": "Signature Verification",
            "check_replay_guard": "Replay Prevention",
            "check_agent_kill_switch": "Kill-Switch Check",
        }
        for i, (bid, cfg) in enumerate(sorted(baselines.items())):
            with cols[i]:
                is_active = bid == active_id
                border = "#3fb950" if bid == "C" else ("#d29922" if bid == "B" else "#f85149")
                st.markdown(f"""
                <div style="border:2px solid {border};border-radius:6px;padding:1rem;background:#161b22">
                    <div style="font-size:1.2rem;font-weight:700;color:{border}">
                        Baseline {bid} {"🔴 ACTIVE" if is_active else ""}
                    </div>
                    <div style="font-size:0.9rem;color:#8b949e;margin-bottom:0.8rem">{cfg.get('name')}</div>
                    <div style="font-size:0.8rem;margin-bottom:0.8rem">{cfg.get('description', '')[:200]}…</div>
                    <div style="font-size:0.75rem;font-weight:600;color:#8b949e;margin-bottom:0.4rem">SECURITY CHECKS</div>
                """, unsafe_allow_html=True)
                checks = cfg.get("checks", {})
                for key, label in check_labels.items():
                    val = checks.get(key, False)
                    icon = "✅" if val else "❌"
                    st.markdown(f"{icon} {label}")
                st.markdown(f"""
                    <div style="margin-top:0.8rem;padding:4px 8px;border-radius:4px;background:{'#0d2d17' if cfg.get('risk_level')=='low' else '#3d1e00' if cfg.get('risk_level')=='critical' else '#0d2b4e'}">
                        Risk: <strong style="color:{border}">{cfg.get('risk_level','').upper()}</strong>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

    # ── Baseline switch ────────────────────────────────────────────────────
    st.markdown("### Change Active Baseline")
    st.warning("⚠ Baselines A and B are intentionally vulnerable. Use synthetic data only.")
    with st.form("change_baseline"):
        col1, col2, col3 = st.columns([1, 2, 1])
        with col1:
            new_baseline = st.selectbox("Select Baseline", ["A", "B", "C"])
        with col2:
            reason = st.text_input("Reason (audited)")
        with col3:
            admin_tok = st.text_input("Admin Token", type="password")
        submitted = st.form_submit_button("Apply Baseline", use_container_width=True)

    if submitted:
        if not admin_tok:
            st.error("Admin token required.")
        else:
            result = set_config(new_baseline, admin_tok, reason)
            if result.get("status") == "success":
                st.success(f"✅ Baseline changed to {new_baseline}. {result.get('message', '')}")
                st.cache_data.clear()
            else:
                st.error(f"❌ {result.get('message', 'Failed to change baseline.')}")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE F — METRICS
# ══════════════════════════════════════════════════════════════════════════════
elif page.startswith("F"):
    st.title("Security Metrics")
    st.markdown("All values computed from actual backend records. Denominators shown explicitly.")

    m = _metrics()
    d = m.get("data", {})
    subs = d.get("submissions", {})
    execs = d.get("executions", {})
    sec = d.get("security", {})

    if m.get("status") == "error":
        st.error(f"Cannot fetch metrics: {m.get('message')}")
    else:
        # ── Submissions ────────────────────────────────────────────────────
        st.markdown("### Authorization Decisions")
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Submissions", subs.get("total", 0))
        with col2:
            st.metric("Allowed", subs.get("allowed", 0))
        with col3:
            st.metric("Denied", subs.get("denied", 0))
        with col4:
            st.metric("Pending Approval", subs.get("require_approval", 0))

        block_rate = subs.get("block_rate")
        if block_rate is not None:
            st.markdown(f"**Block Rate:** `{block_rate:.1%}` — {subs.get('block_rate_denominator', '')}")
        else:
            st.markdown("**Block Rate:** `—` (no submissions yet)")

        # ── Executions ─────────────────────────────────────────────────────
        st.markdown("### Execution Outcomes")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Executions", execs.get("total", 0))
        with col2:
            st.metric("Successful", execs.get("successful", 0))
        with col3:
            st.metric("Failed / Error", execs.get("failed", 0))

        sr = execs.get("success_rate")
        if sr is not None:
            st.markdown(f"**Success Rate:** `{sr:.1%}` — {execs.get('success_rate_denominator', '')}")
        else:
            st.markdown("**Success Rate:** `—` (no executions yet)")

        # ── Security ───────────────────────────────────────────────────────
        st.markdown("### Security Enforcement")
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Unauthorized Executions", sec.get("unauthorized_executions", 0))
        with col2:
            st.metric("Audit Chain Valid", "✅" if sec.get("audit_chain_valid") else "❌")
        with col3:
            st.metric("Audit Records Verified", sec.get("audit_chain_verified_count", 0))

        st.info(f"ℹ **Replay rejections:** {sec.get('replay_rejections', 0)} — {sec.get('replay_rejection_note', '')}")
        st.info(f"ℹ **Audit chain:** {sec.get('audit_chain_note', '')}")

        # ── Breakdown tables ───────────────────────────────────────────────
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Policy Decision Breakdown**")
            breakdown = d.get("policy_breakdown", {})
            if breakdown:
                st.dataframe(
                    pd.DataFrame(list(breakdown.items()), columns=["Decision", "Count"]),
                    hide_index=True, use_container_width=True,
                )
            else:
                _empty("No data")
        with col2:
            st.markdown("**Execution Outcome Breakdown**")
            outcome = d.get("outcome_breakdown", {})
            if outcome:
                st.dataframe(
                    pd.DataFrame(list(outcome.items()), columns=["Outcome", "Count"]),
                    hide_index=True, use_container_width=True,
                )
            else:
                _empty("No data")


# ══════════════════════════════════════════════════════════════════════════════
# PAGE G — AUDIT & EXPORT
# ══════════════════════════════════════════════════════════════════════════════
elif page.startswith("G"):
    st.title("Audit & Export")

    col1, col2 = st.columns([2, 1])
    with col1:
        audit_limit = st.number_input("Max events to load", min_value=10, max_value=1000, value=100, step=10)
    with col2:
        filter_event = st.text_input("Filter event type", "")

    st.cache_data.clear()
    a_data = list_audit(int(audit_limit))
    events = a_data if isinstance(a_data, list) else a_data.get("data", a_data) if isinstance(a_data, dict) else []
    # Handle both list responses and wrapped responses
    if isinstance(events, dict):
        events = events.get("events", [])

    if filter_event:
        events = [e for e in events if filter_event.upper() in e.get("event_type", "").upper()]

    st.markdown(f"**{len(events)} event(s)**")

    if events:
        rows = []
        for e in events:
            rows.append({
                "Seq": e.get("sequence_number", ""),
                "Time": str(e.get("timestamp", ""))[:19],
                "Type": e.get("event_type", ""),
                "Actor": str(e.get("actor_id", ""))[:16] + "…" if len(str(e.get("actor_id", ""))) > 16 else str(e.get("actor_id", "")),
                "Chain Hash": str(e.get("chain_hash", ""))[:12] + "…",
                "Prev Hash": str(e.get("prev_chain_hash", ""))[:12] + "…" if e.get("prev_chain_hash") else "genesis",
            })
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)

        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

        # ── Export ─────────────────────────────────────────────────────────
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "⬇ Export as JSON",
                data=json.dumps(events, indent=2, default=str),
                file_name="agentshield_audit.json",
                mime="application/json",
                use_container_width=True,
            )
        with col2:
            csv_data = pd.DataFrame(rows).to_csv(index=False)
            st.download_button(
                "⬇ Export as CSV",
                data=csv_data,
                file_name="agentshield_audit.csv",
                mime="text/csv",
                use_container_width=True,
            )

        # ── Event detail ───────────────────────────────────────────────────
        with st.expander("🔍 Inspect event data"):
            seq = st.number_input("Event sequence number", min_value=1, value=1, step=1)
            match = next((e for e in events if e.get("sequence_number") == seq), None)
            if match:
                st.json(match)
            else:
                st.info("Event not found in current page. Increase limit.")
    else:
        _empty("No audit events. Actions and decisions will appear here once the system processes requests.")
