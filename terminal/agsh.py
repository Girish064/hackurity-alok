#!/usr/bin/env python3
"""
terminal/agsh.py
AgentShield V3 — AGSH Terminal CLI

Professional command-line interface for the AgentShield platform.
Communicates with the backend API — no direct database access.

Usage:
    python -m terminal.agsh --help
    python -m terminal.agsh status
    python -m terminal.agsh connect <agent_id> --api-key <key>
    python -m terminal.agsh action submit --action ISSUE_REFUND --params '{"amount":"500.00"}'
    python -m terminal.agsh config show
    python -m terminal.agsh config set C
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import typer
import httpx
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box

# ── Add project root to path ───────────────────────────────────────────────
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT))

# ── App and console ────────────────────────────────────────────────────────
app = typer.Typer(
    name="agsh",
    help="AgentShield V3 CLI — Adaptive Zero-Trust Action Security",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=False,
)
action_app = typer.Typer(help="Action commands", no_args_is_help=True)
config_app = typer.Typer(help="Configuration commands", no_args_is_help=True)
app.add_typer(action_app, name="action")
app.add_typer(action_app, name="actions")
app.add_typer(config_app, name="config")

_no_color_default = os.environ.get("NO_COLOR", "").lower() in ("1", "true")
console = Console(stderr=False, no_color=_no_color_default)
err_console = Console(stderr=True, style="red", no_color=_no_color_default)


@app.callback()
def main_callback(
    no_color: bool = typer.Option(False, "--no-color", help="Disable color output"),
):
    global console, err_console
    if no_color or _no_color_default:
        console = Console(stderr=False, no_color=True)
        err_console = Console(stderr=True, style=None, no_color=True)

# ── Session state (file-backed) ─────────────────────────────────────────────
def _get_session_file() -> Path:
    return Path.home() / ".agsh_session.json"


def _load_session() -> dict:
    try:
        f = _get_session_file()
        if f.exists():
            return json.loads(f.read_text())
    except Exception:
        pass
    return {}


def _save_session(data: dict) -> None:
    try:
        _get_session_file().write_text(json.dumps(data, indent=2))
    except Exception:
        pass


def _get_api_url() -> str:
    return os.environ.get("AGENTSHIELD_API_URL", "http://localhost:8000")


def _get_api_key() -> Optional[str]:
    session = _load_session()
    return session.get("api_key") or os.environ.get("AGENTSHIELD_API_KEY")


def _get_admin_token() -> Optional[str]:
    return os.environ.get("ADMIN_SECRET_TOKEN") or os.environ.get("AGENTSHIELD_ADMIN_TOKEN")


# ── HTTP helpers ───────────────────────────────────────────────────────────

def _get(path: str, params: Optional[dict] = None, admin: bool = False) -> dict:
    url = _get_api_url() + path
    headers = {}
    if admin:
        tok = _get_admin_token()
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
    try:
        r = httpx.get(url, params=params, headers=headers, timeout=10.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        return {"status": "error", "code": "API_UNREACHABLE", "message": f"Cannot connect to {_get_api_url()}. Is the backend running?"}
    except httpx.HTTPStatusError as exc:
        try:
            body = exc.response.json()
        except Exception:
            body = {}
        return {"status": "error", "code": f"HTTP_{exc.response.status_code}", "message": body.get("message", str(exc))}
    except Exception as exc:
        return {"status": "error", "code": "CLIENT_ERROR", "message": str(exc)}


def _post(path: str, data: dict, admin: bool = False, agent: bool = False) -> dict:
    url = _get_api_url() + path
    headers = {"Content-Type": "application/json"}
    if admin:
        tok = _get_admin_token()
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
    elif agent:
        key = _get_api_key()
        if key:
            headers["Authorization"] = f"Bearer {key}"
    try:
        r = httpx.post(url, json=data, headers=headers, timeout=15.0)
        r.raise_for_status()
        return r.json()
    except httpx.ConnectError:
        return {"status": "error", "code": "API_UNREACHABLE", "message": f"Cannot connect to {_get_api_url()}. Is the backend running?"}
    except httpx.HTTPStatusError as exc:
        try:
            body = exc.response.json()
        except Exception:
            body = {}
        return {"status": "error", "code": f"HTTP_{exc.response.status_code}", "message": body.get("message", str(exc))}
    except Exception as exc:
        return {"status": "error", "code": "CLIENT_ERROR", "message": str(exc)}


# ── Output helpers ─────────────────────────────────────────────────────────

def _ok(msg: str):
    console.print(f"[bold green]✓[/bold green] {msg}")

def _warn(msg: str):
    console.print(f"[bold yellow]⚠[/bold yellow] {msg}")

def _err(msg: str):
    console.print(f"[bold red]✗[/bold red] {msg}")

def _info(msg: str):
    console.print(f"[blue]·[/blue] {msg}")

def _print_response(result: dict):
    status = result.get("status", "")
    msg = result.get("message", "")
    code = result.get("code", "")
    if status == "success":
        _ok(f"[{code}] {msg}")
    elif status == "blocked":
        _warn(f"[{code}] {msg}")
    elif status == "error":
        _err(f"[{code}] {msg}")
    else:
        _info(msg)


# ══════════════════════════════════════════════════════════════════════════════
# COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

@app.command()
def connect(
    agent_id: str = typer.Argument(help="Agent ID to connect as"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="Agent API key (stored in session, never logged)"),
    api_url: str = typer.Option("http://localhost:8000", "--url", help="Backend API URL"),
):
    """Connect to AgentShield as an agent. Saves session context."""
    if not api_key:
        api_key = typer.prompt("Agent API key", hide_input=True)

    if not api_key or len(api_key) < 8:
        _err("API key must be at least 8 characters.")
        raise typer.Exit(1)

    session = _load_session()
    session["agent_id"] = agent_id
    session["api_key"] = api_key  # stored locally only
    session["api_url"] = api_url
    _save_session(session)
    os.environ["AGENTSHIELD_API_URL"] = api_url

    _ok(f"Connected as agent [bold]{agent_id}[/bold] → {api_url}")
    _info("Session saved. API key stored in ~/.agsh_session.json (local only — never transmitted in logs).")


@app.command()
def status():
    """Show system status, active baseline, and component health."""
    result = _get("/health")
    s_result = _get("/system/status")

    if result.get("code") == "API_UNREACHABLE":
        _err(result.get("message"))
        raise typer.Exit(1)

    data = result.get("data", {})
    s_data = s_result.get("data", {})
    overall = data.get("overall", "unknown")

    console.print()
    console.print(Panel.fit(
        f"[bold]AgentShield V3[/bold] — {_get_api_url()}\n"
        f"Status: [{'bold green' if overall=='ok' else 'bold red'}]{overall.upper()}[/]\n"
        f"Baseline: [bold cyan]{s_data.get('active_baseline', '?')}[/] — {s_data.get('baseline_name', '')}",
        title="🛡 System Status",
        border_style="blue",
    ))
    console.print()

    # Components
    table = Table("Component", "Status", box=box.SIMPLE_HEAVY, show_header=True, header_style="bold cyan")
    for name, st_val in data.get("components", {}).items():
        color = "green" if st_val == "ok" else ("yellow" if "disabled" in st_val else "red")
        table.add_row(name.replace("_", " ").title(), f"[{color}]{st_val}[/]")
    console.print(table)

    # Session
    session = _load_session()
    if session.get("agent_id"):
        _info(f"Session: agent [bold]{session['agent_id']}[/bold]")
    else:
        _warn("No session. Run: agsh connect <agent_id> --api-key <key>")


# ── action sub-commands ────────────────────────────────────────────────────

@action_app.command("submit")
def action_submit(
    action_type: str = typer.Option("ISSUE_REFUND", "--action", "-a", help="Action type (e.g. ISSUE_REFUND)"),
    params: str = typer.Option("{}", "--params", "-p", help="JSON parameters string"),
    scope: float = typer.Option(0.0, "--scope", "-s", help="Numeric scope (e.g. amount for refunds)"),
    capability_token: Optional[str] = typer.Option(None, "--token", "--capability", help="Signed capability token for direct execution"),
    request_id: Optional[str] = typer.Option(None, "--request-id", help="Idempotency UUID (auto-generated if omitted)"),
    execute: bool = typer.Option(False, "--execute", "-x", help="Immediately execute action upon capability issuance"),
):
    """Submit an action for authorization and optional execution."""
    # Validate JSON
    try:
        parameters = json.loads(params)
    except json.JSONDecodeError as exc:
        _err(f"Invalid JSON in --params: {exc}")
        raise typer.Exit(1)

    if not isinstance(parameters, dict):
        _err("--params must be a JSON object (dict), not an array or scalar.")
        raise typer.Exit(1)

    if scope > 0 and "amount" not in parameters:
        parameters["amount"] = str(scope)

    payload: dict[str, Any] = {
        "action_type": action_type.upper(),
        "parameters": parameters,
    }
    if request_id:
        payload["request_id"] = request_id
    if capability_token:
        payload["capability_token"] = capability_token

    _info(f"Submitting {action_type.upper()} with parameters: {json.dumps(parameters)}")
    result = _post("/actions/submit", payload, agent=True)
    _print_response(result)

    data = result.get("data", {})
    decision = data.get("decision", "")

    if result.get("code") == "ACTION_EXECUTED":
        console.print()
        _ok("Action executed successfully.")
        console.print(f"  [dim]Execution ID:[/dim]  {data.get('execution_id', '')}")
        console.print(f"  [dim]Outcome:[/dim]       {data.get('outcome', '')}")
        console.print(f"  [dim]Executed At:[/dim]   {data.get('executed_at', '')}")
        rec = data.get("receipt_token", "")
        if rec:
            console.print(f"  [dim]Receipt token:[/dim] {rec[:40]}…")
        return

    if decision == "ALLOW":
        console.print()
        _ok("Capability issued. Token ready for execution.")
        cap_token = data.get("capability_token", "")
        if cap_token:
            console.print(f"  [dim]Capability token:[/dim] {cap_token[:40]}…")
            console.print(f"  [dim]Expires at:[/dim]       {data.get('expires_at', '')}")
            console.print(f"  [dim]Action digest:[/dim]    {data.get('action_digest', '')}")

        if execute and cap_token:
            _info("Immediately submitting capability for protected execution...")
            exec_payload = {
                "action_type": action_type.upper(),
                "parameters": parameters,
                "capability_token": cap_token,
            }
            exec_result = _post("/actions/submit", exec_payload, agent=True)
            _print_response(exec_result)
            edata = exec_result.get("data", {})
            if exec_result.get("status") == "success":
                _ok("Action executed successfully.")
                console.print(f"  [dim]Execution ID:[/dim]  {edata.get('execution_id', '')}")
                console.print(f"  [dim]Outcome:[/dim]       {edata.get('outcome', '')}")
                console.print(f"  [dim]Executed At:[/dim]   {edata.get('executed_at', '')}")
    elif decision == "REQUIRE_APPROVAL":
        _warn(f"Human approval required. Approval ID: {data.get('approval_id', '')}")
        _info("An admin must approve via POST /approvals/{id}/decide before you can execute.")
    elif result.get("status") == "blocked":
        _warn(f"Action blocked by policy. Code: {result.get('code')}")
    elif result.get("status") == "error":
        _err(f"Submission error: {result.get('message')}")


@action_app.command("list")
def action_list(
    limit: int = typer.Option(20, "--limit", "-n"),
    status_filter: Optional[str] = typer.Option(None, "--status", help="Filter by status"),
):
    """List recent action requests."""
    params = {"limit": limit}
    if status_filter:
        params["status"] = status_filter
    result = _get("/actions", params=params)
    actions = result.get("data", {}).get("actions", [])

    if not actions:
        _info("No actions found.")
        return

    table = Table(
        "Time", "Request ID", "Type", "Decision", "Status",
        box=box.SIMPLE_HEAVY, header_style="bold cyan", show_header=True,
    )
    for a in actions:
        ts = str(a.get("submitted_at", ""))[:16]
        rid = str(a.get("request_id", ""))[:8] + "…"
        atype = a.get("action_type", "")
        decision = a.get("policy_decision", "")
        stat = a.get("status", "")
        d_color = "green" if decision == "ALLOW" else ("red" if decision == "DENY" else "yellow")
        s_color = "green" if stat == "executed" else ("red" if stat == "denied" else "yellow")
        table.add_row(ts, rid, atype, f"[{d_color}]{decision}[/]", f"[{s_color}]{stat}[/]")

    console.print(table)


# ── ledger ─────────────────────────────────────────────────────────────────

@app.command()
def ledger(
    subcommand: Optional[str] = typer.Argument(None, help="Subcommand: list (default)"),
    limit: int = typer.Option(20, "--limit", "-n", help="Max records to show"),
):
    """List execution receipts (the execution ledger). Usage: agsh ledger OR agsh ledger list"""
    result = _get("/receipts", params={"limit": limit})
    receipts = result.get("data", {}).get("receipts", [])

    if not receipts:
        _info("No execution records yet.")
        return

    table = Table(
        "Execution ID", "Agent", "Tool", "Outcome", "Has Receipt", "Executed At",
        box=box.SIMPLE_HEAVY, header_style="bold cyan",
    )
    for r in receipts:
        eid = str(r.get("execution_id", ""))[:8] + "…"
        agent = str(r.get("agent_id", ""))[:8] + "…"
        tool = r.get("tool_name", "")
        outcome = r.get("outcome", "")
        has_rec = "✓" if r.get("has_receipt") else "✗"
        ts = str(r.get("executed_at", ""))[:16]
        o_color = "green" if outcome == "success" else "red"
        table.add_row(eid, agent, tool, f"[{o_color}]{outcome}[/]", has_rec, ts)

    console.print(table)


# ── receipt verify ─────────────────────────────────────────────────────────

@app.command()
def receipt(
    arg1: str = typer.Argument(help="Path to receipt JWT file, or 'verify' subcommand"),
    arg2: Optional[str] = typer.Argument(None, help="Path to receipt JWT file (if using 'agsh receipt verify <file>')"),
):
    """Verify a signed execution receipt. Usage: agsh receipt verify <file> OR agsh receipt <file>"""
    receipt_file = arg2 if (arg1 == "verify" and arg2) else arg1
    if receipt_file == "-":
        token = sys.stdin.read().strip()
    else:
        try:
            token = Path(receipt_file).read_text().strip()
        except FileNotFoundError:
            _err(f"File not found: {receipt_file}")
            raise typer.Exit(1)

    if not token:
        _err("Empty receipt token.")
        raise typer.Exit(1)

    result = _post("/receipts/verify", {"receipt_token": token})
    _print_response(result)

    data = result.get("data", {})
    if data.get("valid"):
        console.print()
        console.print(f"  [dim]Capability ID:[/dim] {data.get('capability_id', '')}")
        console.print(f"  [dim]Action Digest:[/dim] {data.get('action_digest', '')}")
        console.print(f"  [dim]Executor ID:[/dim]   {data.get('executor_id', '')}")
        console.print(f"  [dim]Outcome:[/dim]        {data.get('outcome', '')}")
        console.print(f"  [dim]Executed At:[/dim]   {data.get('executed_at', '')}")


# ── audit ──────────────────────────────────────────────────────────────────

@app.command()
def audit(
    subcommand: Optional[str] = typer.Argument(None, help="Subcommand: tail, list (optional)"),
    limit: int = typer.Option(20, "--limit", "-n", help="Number of events to show"),
    event_type: Optional[str] = typer.Option(None, "--type", help="Filter by event type"),
):
    """Show the audit trail (most recent events first). Usage: agsh audit OR agsh audit tail"""
    params: dict = {"limit": limit}
    if event_type:
        params["event_type"] = event_type.upper()
    result = _get("/audit", params=params)
    events = (
        result.get("data", {}).get("events", [])
        if isinstance(result, dict)
        else (result if isinstance(result, list) else [])
    )

    if not events:
        _info("No audit events found.")
        return

    table = Table(
        "Seq", "Time", "Event Type", "Actor",
        box=box.SIMPLE_HEAVY, header_style="bold cyan",
    )
    for e in reversed(events[-limit:]):
        seq = str(e.get("sequence_number", ""))
        ts = str(e.get("timestamp", ""))[:16]
        etype = e.get("event_type", "")
        actor = str(e.get("actor_id", ""))[:20] + ("…" if len(str(e.get("actor_id", ""))) > 20 else "")
        e_color = "green" if "SUCCESS" in etype else ("red" if any(x in etype for x in ["DENY", "FAIL", "REVOKE"]) else "cyan")
        table.add_row(seq, ts, f"[{e_color}]{etype}[/]", actor)

    console.print(table)


# ── metrics ────────────────────────────────────────────────────────────────

@app.command()
def metrics(
    subcommand: Optional[str] = typer.Argument(None, help="Subcommand: show (optional)"),
):
    """Show security metrics from actual backend records. Usage: agsh metrics OR agsh metrics show"""
    result = _get("/metrics")
    d = result.get("data", {})

    if result.get("status") == "error":
        _err(f"Cannot fetch metrics: {result.get('message')}")
        raise typer.Exit(1)

    console.print()
    subs = d.get("submissions", {})
    execs = d.get("executions", {})
    sec = d.get("security", {})

    console.print(Panel(
        f"Total Submissions:    [bold cyan]{subs.get('total', 0)}[/]\n"
        f"  Allowed:            [green]{subs.get('allowed', 0)}[/]\n"
        f"  Denied:             [red]{subs.get('denied', 0)}[/]\n"
        f"  Pending Approval:   [yellow]{subs.get('require_approval', 0)}[/]\n"
        f"  Block Rate:         {(subs.get('block_rate') or 0):.1%}  ({subs.get('block_rate_denominator','')})\n\n"
        f"Total Executions:     [bold cyan]{execs.get('total', 0)}[/]\n"
        f"  Successful:         [green]{execs.get('successful', 0)}[/]\n"
        f"  Failed/Error:       [red]{execs.get('failed', 0)}[/]\n"
        f"  Success Rate:       {(execs.get('success_rate') or 0):.1%}\n\n"
        f"Unauthorized Execs:   [bold red]{sec.get('unauthorized_executions', 0)}[/]\n"
        f"Audit Chain Valid:    [{'green' if sec.get('audit_chain_valid') else 'red'}]{sec.get('audit_chain_valid')}[/]\n"
        f"Audit Records:        {sec.get('audit_chain_verified_count', 0)}",
        title="Security Metrics",
        border_style="blue",
    ))


# ── config sub-commands ────────────────────────────────────────────────────

@config_app.command("show")
def config_show():
    """Show the active baseline configuration."""
    result = _get("/config")
    d = result.get("data", {})

    if result.get("status") == "error":
        _err(result.get("message"))
        raise typer.Exit(1)

    active = d.get("active_baseline", {})
    bid = active.get("id", "?")
    risk_colors = {"low": "green", "medium": "yellow", "high": "red", "critical": "red"}
    risk = active.get("risk_level", "unknown")

    console.print(Panel(
        f"Active Baseline: [bold cyan]{bid}[/] — {active.get('name', '')}\n"
        f"Risk Level:      [{risk_colors.get(risk,'white')}]{risk.upper()}[/]\n\n"
        + "\n".join(
            f"  {'[green]✓[/]' if v else '[red]✗[/]'} {k.replace('_',' ')}"
            for k, v in active.get("checks", {}).items()
        ),
        title="Active Configuration",
        border_style="cyan",
    ))

    if bid in ("A", "B"):
        _warn("This is an intentionally VULNERABLE configuration. Use synthetic data only.")
    else:
        _ok("Baseline C — Full enforcement active.")


@config_app.command("set")
def config_set(
    baseline: str = typer.Argument(help="Baseline to activate: A, B, or C"),
    reason: str = typer.Option("", "--reason", help="Reason for change (audited)"),
):
    """Change the active baseline. Requires ADMIN_SECRET_TOKEN environment variable."""
    if baseline.upper() not in ("A", "B", "C"):
        _err("Baseline must be A, B, or C.")
        raise typer.Exit(1)

    admin_token = _get_admin_token()
    if not admin_token:
        _err("ADMIN_SECRET_TOKEN (or AGENTSHIELD_ADMIN_TOKEN) environment variable not set.")
        raise typer.Exit(1)

    if baseline.upper() in ("A", "B"):
        _warn(f"Baseline {baseline.upper()} is INTENTIONALLY VULNERABLE. Only use with synthetic data.")
        confirm = typer.confirm("Proceed?")
        if not confirm:
            _info("Aborted.")
            raise typer.Exit(0)

    result = _post(
        "/config",
        {"baseline": baseline.upper(), "reason": reason},
        admin=True,
    )
    _print_response(result)
    if result.get("status") == "success":
        _ok(f"Baseline set to {baseline.upper()}. Change is audited.")


# ── reset ──────────────────────────────────────────────────────────────────

@app.command()
def reset(
    demo: bool = typer.Option(False, "--demo", help="Reset synthetic demo data"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt"),
):
    """Reset synthetic demo data safely. Does NOT touch real data or credentials."""
    if not demo:
        _err("Specify --demo to reset demo data. Use --yes to skip confirmation.")
        raise typer.Exit(1)

    if not confirm:
        proceed = typer.confirm(
            "Reset all synthetic demo data? This clears the local session context only.",
        )
        if not proceed:
            _info("Reset cancelled.")
            raise typer.Exit(0)

    # Clear local session context
    try:
        sf = _get_session_file()
        if sf.exists():
            sf.unlink()
    except Exception as exc:
        _warn(f"Could not clear session: {exc}")

    _ok("Demo session context cleared.")
    _info("To reset the backend database, restart with 'alembic downgrade base && alembic upgrade head'.")
    _info("This CLI only clears your local session (~/.agsh_session.json).")


# ── Entry point ────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app()
