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
from secagent.core.scheduler import JobManager
from secagent.server.tools_registry import (
    _POLL_RESULT_SCHEMA,
    _SUBMIT_SCAN_SCHEMA,
    ToolDefinition,
    all_tools,
)
from secagent.storage.sqlite_store import SQLiteStore

_JSON_TYPE_NAMES = {
    "array": "array",
    "integer": "integer",
    "object": "object",
    "string": "string",
}


def _matches_json_type(value: Any, schema_type: str) -> bool:
    if schema_type == "array":
        return isinstance(value, list)
    if schema_type == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if schema_type == "object":
        return isinstance(value, dict)
    if schema_type == "string":
        return isinstance(value, str)
    return True


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
        self.job_manager = JobManager(config=self.config)

        # Build tool map: sync tools from all_tools() + async tools
        self._tools: dict[str, ToolDefinition] = {td.name: td for td in all_tools()}
        self._tools["submit_scan"] = ToolDefinition(
            name="submit_scan",
            description=(
                "Submit a slow scan (attack_surface_scan, probe_services, "
                "gather_osint, scan_vulnerabilities, scan_ports, "
                "discover_paths) for async execution. "
                "Returns a job_id immediately; use poll_result to retrieve "
                "findings when done."
            ),
            input_schema=_SUBMIT_SCAN_SCHEMA,
            handler=self._handle_submit_scan,
        )
        self._tools["poll_result"] = ToolDefinition(
            name="poll_result",
            description=(
                "Poll the result of an async scan job previously submitted "
                "via submit_scan. Returns status='running' if still in "
                "progress, or status='done' with findings when complete."
            ),
            input_schema=_POLL_RESULT_SCHEMA,
            handler=self._handle_poll_result,
        )

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

        properties = td.input_schema.get("properties", {})
        for key, value in args.items():
            schema_type = properties.get(key, {}).get("type")
            if value is None or schema_type not in _JSON_TYPE_NAMES:
                continue
            if not _matches_json_type(value, schema_type):
                return {
                    "error": {
                        "code": "INVALID_INPUT",
                        "message": (
                            f"Invalid type for argument '{key}' in tool '{name}': "
                            f"expected {_JSON_TYPE_NAMES[schema_type]}."
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

    # ------------------------------------------------------------------
    # Async tool handlers (submit_scan / poll_result)
    # ------------------------------------------------------------------

    def _handle_submit_scan(
        self, gate: ComplianceGate, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Submit a slow tool for async execution."""
        tool = args.get("tool", "")
        params = args.get("params", {})
        authz_token = args.get("authz_token", "")
        caller_id = args.get("caller_id", "mcp-client")
        return self.job_manager.submit_scan(
            tool=tool,
            params=params,
            authz_token=authz_token,
            caller_id=caller_id,
        )

    def _handle_poll_result(
        self, gate: ComplianceGate, args: dict[str, Any]
    ) -> dict[str, Any]:
        """Poll the result of a previously submitted async scan."""
        job_id = args.get("job_id", "")
        return self.job_manager.poll_result(job_id=job_id)
