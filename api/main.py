"""
api/main.py
AgentShield V3 — Unified FastAPI Gateway.

Exposes a clean, documented REST API for:
  - System health and component status
  - Adaptive policy evaluation and capability issuance
  - Action submission and protected execution
  - Execution receipts and cryptographic verification
  - Hash-chained audit event retrieval and chain verification
  - Security demonstration metrics
  - Baseline configuration (A: Minimal, B: Gateway-only, C: Full enforcement)

Consistent JSON response contract across endpoints:
  {
      "status": "success|blocked|error",
      "code": "...",
      "message": "...",
      "data": {},
      "request_id": "..."
  }
"""
from __future__ import annotations

import uvicorn
from backend.main import app, create_app

__all__ = ["app", "create_app"]

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("api.main:app", host=host, port=port, reload=True)
