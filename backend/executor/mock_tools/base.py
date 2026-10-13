"""
backend/executor/mock_tools/base.py
Abstract base class for mock protected tools.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class ToolResult:
    success: bool
    outcome: str          # "success" | "failure" | "tool_error"
    data: dict


class MockTool(ABC):
    """Abstract base for all mock protected tools."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Unique name for this tool."""

    @abstractmethod
    async def execute(self, parameters: dict) -> ToolResult:
        """
        Execute the mock tool.

        This must NOT connect to real external services.
        It must NOT expose real credentials.
        """
