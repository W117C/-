"""BaseAdapter — the interface every tool adapter must implement.

Every adapter receives params, runs a binary via Launcher, parses its output,
and returns a list of Finding objects. The ComplianceGate is the caller's
responsibility (it wraps the adapter call, not the adapter itself).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from secagent.core.finding import Finding


class BaseAdapter(ABC):
    """Abstract base for tool adapters. Subclass per open-source tool."""

    @property
    @abstractmethod
    def tool_name(self) -> str:
        """Name used in versions.py and Finding.source_tool."""

    @abstractmethod
    def run(self, params: dict[str, Any]) -> list[Finding]:
        """Execute the tool with given params, return findings.

        The adapter is responsible for:
        1. Translating params → CLI command
        2. Calling Launcher.run()
        3. Parsing tool-specific JSON output → list[Finding]
        """
