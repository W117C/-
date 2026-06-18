"""SecAgentServer — MCP application core (spec §3, §7.2 M2b).

This is the single choke point between the MCP transport layer
(`__main__.py`) and the compliance-gated tool functions (`secagent.tools.*`).
It owns no MCP SDK dependency, so it is fully unit-testable with the existing
pytest stack.

Responsibilities:
  1. Load Config + bootstrap SQLite + construct ComplianceGate (reuses the
     same wiring as `secagent.cli.authz`, so CLI-issued tokens work here).
  2. Expose `list_tools()` for the MCP `tools/list` request.
  3. Dispatch `call_tool(name, arguments)` to the registered handler,
     catching every `SecAgentError` and converting it to the unified error
     dict (spec §3.1). Unexpected exceptions become TOOL_FAILED.
  4. Validate required arguments before dispatch so callers get a clear
     INVALID_INPUT instead of a confusing downstream KeyError.
"""
from __future__ import annotations

from typing import Any

from secagent.config import Config
from secagent.core.errors import SecAgentError, to_error_dict
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.server.tools_registry import ToolDefinition, all_tools
from secagent.storage.sqlite_store import SQLiteStore


class SecAgentServer:
    """Application core. One instance per server process."""

    def __init__(self, config: Config | None = None):
        self.config = config or Config.load()
        self.store = SQLiteStore(self.config.db_path)
        self.store.bootstrap()
        self.registry = AuthorizationRegistry(
            self.store, default_quota=self.config.default_quota_per_token
        )
        self.gate = ComplianceGate(
            self.store,
            self.registry.quota,
            default_quota=self.config.default_quota_per_token,
        )
        self._tools: dict[str, ToolDefinition] = {td.name: td for td in all_tools()}

    def list_tools(self) -> list[ToolDefinition]:
        """All currently registered tools (MCP `tools/list` response source)."""
        return list(self._tools.values())

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Dispatch a tool call. Never raises on expected errors — returns
        the unified error dict (spec §3.1) so the MCP layer can pass it
        straight to the agent as tool output."""
        td = self._tools.get(name)
        if td is None:
            return {
                "error": {
                    "code": "INVALID_INPUT",
                    "message": (
                        f"Unknown tool '{name}'. Available: "
                        f"{sorted(self._tools.keys())}"
                    ),
                    "retryable": False,
                }
            }

        # Required-argument validation (cheap, gives clearer errors than the
        # tool function's own checks).
        args = arguments or {}
        for req in td.input_schema.get("required", []):
            if req not in args or args[req] in (None, ""):
                return {
                    "error": {
                        "code": "INVALID_INPUT",
                        "message": (
                            f"Missing required argument '{req}' for tool '{name}'."
                        ),
                        "retryable": False,
                    }
                }

        try:
            return td.handler(self.gate, args)
        except SecAgentError as exc:
            return to_error_dict(exc)
        except Exception as exc:  # noqa: BLE001 — last-resort guard for the agent
            return {
                "error": {
                    "code": "TOOL_FAILED",
                    "message": f"Unexpected error in tool '{name}': {exc}",
                    "retryable": False,
                }
            }
