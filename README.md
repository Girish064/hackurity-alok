# AgentShield — Zero-Trust Action Security for AI Agents

## Overview

AgentShield is a security enforcement layer that sits between AI agents and the protected tools they call.

**Core principle**: Authentication identifies *who* the agent is. AgentShield evaluates whether *this specific action, right now, with these exact parameters* is authorized, and the protected executor independently verifies that authorization before executing.

## Quick Start

### Prerequisites
- Python 3.11+
- Docker + Docker Compose
- `pip install -e ".[dev]"`

### 1. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in key values (see .env.example for instructions)
# At minimum, generate Ed25519 keys:
python -c "
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, PublicFormat, NoEncryption
k = Ed25519PrivateKey.generate()
print('AGENTSHIELD_SIGNING_KEY_PEM=' + k.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode().replace(chr(10), r'\n'))
print('AGENTSHIELD_VERIFYING_KEY_PEM=' + k.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode().replace(chr(10), r'\n'))
"
```

### 2. Start infrastructure

```bash
docker-compose up -d postgres redis
```

### 3. Run migrations

```bash
alembic upgrade head
```

### 4. Start the backend

```bash
uvicorn backend.main:app --reload
# API docs: http://localhost:8000/docs
```

### 5. Run the demo (Scenario A)

```bash
python agents/legitimate_agent/agent.py --scenario A
```

### 6. Run adversarial scenarios

```bash
python agents/compromised_agent/agent.py --scenario B   # Tampered action
python agents/compromised_agent/agent.py --scenario C   # Replay attack
python agents/compromised_agent/agent.py --scenario E   # Revoked agent
python agents/compromised_agent/agent.py --scenario G   # Direct bypass
```

## Running Tests

```bash
# Unit tests (no external services)
pytest tests/unit/ -v

# Security invariant tests (fakeredis + SQLite)
pytest tests/security/ -v

# All tests
pytest -v
```

## Architecture

```
AI Agent
   │
   ▼
AgentShield Gateway (FastAPI)
   ├── Agent authentication (API key → SHA-256 hash lookup)
   ├── Rate limiting (Redis sliding window)
   ├── Policy evaluation (deterministic rules — ALLOW/DENY/REQUIRE_APPROVAL)
   ├── Canonicalization + SHA-256 digest (security module)
   └── Signed capability issuance (Ed25519 JWT)
   │
   ▼
Protected Executor (FastAPI)
   ├── Re-canonicalize + re-digest (must match capability)
   ├── verify_capability() — Ed25519 signature + all binding claims
   ├── Kill-switch check (Redis)
   ├── Atomic capability consumption (Redis SET NX EX)
   ├── Execute mock tool
   ├── Sign execution receipt
   └── Append audit record (hash chain)
   │
   ▼
PostgreSQL + Redis + Audit Chain
```

## Module Ownership

| Module | Owner |
|---|---|
| `backend/`, `core/`, `terminal/`, `dashboard/`, `api/` | Alok (Platform, Terminal, Adaptive Policy Engine, Dashboard, System Integration) |
| `security/` | Girish (Cryptographic modules, canonicalization, action digest, receipt signing, verification) |
| `agents/` | Gururaj (Demo scenarios, adversarial attack scripts, red-team observer) |

## Security Properties

1. Every sensitive action passes an independent enforcement boundary.
2. Valid agent identity does not automatically authorize every action.
3. The executor verifies authorization independently — not delegated to the gateway.
4. Capabilities are bound to exact: agent, tenant, action digest, and executor.
5. Parameter changes after approval are detected by digest re-computation.
6. Each capability authorizes at most one execution (atomic Redis consumption).
7. Expired, revoked, and consumed capabilities are rejected.
8. Hard policy denials cannot be overridden.

**Hash-chain limitation**: The audit chain detects modification and reordering of records within a query result. It cannot detect deletion of records or replacement of the entire chain. This is documented and the system makes no stronger guarantee.

## Unified API Gateway Endpoints

| Method | Path | Description | Response Contract |
|---|---|---|---|
| GET | `/health` | Service health & dependency status | Standard envelope |
| GET | `/system/status` | Active baseline & module availability | Standard envelope |
| POST | `/capabilities/issue` | Request capability with adaptive policy scoring | Standard envelope |
| POST | `/actions/submit` | Submit action & capability for protected execution | Standard envelope |
| GET | `/actions` | List recent action requests and outcomes | Standard envelope |
| GET | `/actions/{id}` | Retrieve single action request | Standard envelope |
| GET | `/receipts` | List available execution receipts | Standard envelope |
| POST | `/receipts/verify` | Cryptographically verify execution receipt | Standard envelope |
| GET | `/audit` | Retrieve audit events (standard contract) | Standard envelope |
| GET | `/audit/events` | List audit events (legacy list format) | Array of events |
| POST | `/audit/verify-chain` | Verify cryptographic hash chain integrity | Verification report |
| GET | `/metrics` | Security demonstration metrics | Standard envelope |
| GET | `/config` | Read active baseline configuration | Standard envelope |
| POST | `/config` | Switch baseline A/B/C (admin authorized) | Standard envelope |

### Standard Response Envelope

```json
{
  "status": "success|blocked|error",
  "code": "CAPABILITY_ISSUED",
  "message": "Human-readable description",
  "data": { ... },
  "request_id": "00000000-0000-0000-0000-000000000000"
}
```

## AGSH Terminal CLI

The AgentShield Terminal CLI (`terminal/agsh.py`) connects directly to the platform API:

```bash
# Connect agent
python -m terminal.agsh connect <agent_id> --api-key <key>

# System & component status
python -m terminal.agsh status

# Submit action for capability / execution
python -m terminal.agsh action submit --action ISSUE_REFUND --params '{"amount":"500.00"}' --scope 500
python -m terminal.agsh action submit --action ISSUE_REFUND --params '{"amount":"500.00"}' --execute

# List action submissions
python -m terminal.agsh actions list

# View execution ledger
python -m terminal.agsh ledger list

# Verify signed execution receipt
python -m terminal.agsh receipt verify <receipt_file>

# Tail audit trail
python -m terminal.agsh audit tail

# Display security metrics
python -m terminal.agsh metrics show

# Configuration control
python -m terminal.agsh config show
python -m terminal.agsh config set C   # Full enforcement
python -m terminal.agsh config set A   # Minimal protection (test only)

# Reset demo session context
python -m terminal.agsh reset --demo --yes
```

## Defender Dashboard

Launch the cybersecurity operations console:

```bash
streamlit run dashboard/app.py
```

Sections:
- **A. System Overview**: Real-time health, active baseline, module status.
- **B. Live Action Feed**: Actions, decisions, outcomes, block reasons.
- **C. Adaptive Trust**: Real-time confidence scores, risk level, dynamic TTL.
- **D. Security Evidence**: Capability verification, digest comparisons, receipts.
- **E. Baseline Comparison**: Side-by-side comparison of Baselines A, B, and C.
- **F. Metrics**: Real block rates, execution rates, replay rejections, audit status.
- **G. Audit & Export**: Hash chain verification, JSON/CSV exports.

