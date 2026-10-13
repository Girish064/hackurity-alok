"""
backend/executor/mock_tools/refund_tool.py
Simulated payment refund tool.

IMPORTANT: This tool does NOT connect to real payment services.
It does NOT use real financial credentials.
It simulates a refund and records the outcome in a predictable way for testing.

The tool fails deterministically for amounts ending in .99 (for failure path testing).
"""
from __future__ import annotations

import uuid
from decimal import Decimal

from backend.executor.mock_tools.base import MockTool, ToolResult


class RefundTool(MockTool):
    """
    Simulates issuing a payment refund.

    Parameters expected in `parameters` dict:
      amount   : str   — refund amount as string (e.g. "500.00")
      currency : str   — currency code (e.g. "INR")
      order_id : str   — order identifier

    Returns a fake refund_id and status.
    """

    @property
    def tool_name(self) -> str:
        return "refund_tool"

    async def execute(self, parameters: dict) -> ToolResult:
        amount_str = parameters.get("amount", "0")
        currency = parameters.get("currency", "INR")
        order_id = parameters.get("order_id", "UNKNOWN")

        try:
            amount = Decimal(str(amount_str))
        except Exception:
            return ToolResult(
                success=False,
                outcome="tool_error",
                data={"error": f"Invalid amount: {amount_str!r}"},
            )

        # Deterministic failure for testing (amount ends in .99 cents)
        if amount % 1 == Decimal("0.99"):
            return ToolResult(
                success=False,
                outcome="failure",
                data={
                    "error": "Simulated payment processor failure",
                    "order_id": order_id,
                    "amount": str(amount),
                    "currency": currency,
                },
            )

        # Simulate success
        refund_id = f"REF-{uuid.uuid4().hex[:8].upper()}"
        return ToolResult(
            success=True,
            outcome="success",
            data={
                "refund_id": refund_id,
                "status": "processed",
                "amount": str(amount),
                "currency": currency,
                "order_id": order_id,
                "message": (
                    f"Mock refund of {currency} {amount} for order "
                    f"{order_id!r} processed successfully."
                ),
            },
        )


# Registry: maps action_type → tool instance
TOOL_REGISTRY: dict[str, MockTool] = {
    "ISSUE_REFUND": RefundTool(),
}
