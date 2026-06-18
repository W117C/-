"""Declarative tool registry — schema + handler for each MCP tool (spec §3.2).

Adding a new tool in M3 = append one `ToolDefinition` to `all_tools()` and
write a thin handler that adapts `(gate, arguments)` to the existing tool
function signature. No changes to `app.py` or `__main__.py` needed.

Each handler receives the shared `ComplianceGate` (so authorization/blocklist/
audit/quota all flow through it) and the raw MCP arguments dict. It returns
the unified output structure (spec §3.1) on success, or raises a
`SecAgentError` subclass — `SecAgentServer.call_tool` converts those to the
unified error dict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from secagent.core.gate import ComplianceGate


@dataclass(frozen=True)
class ToolDefinition:
    """One MCP tool: its JSON-Schema input contract and dispatch handler."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[ComplianceGate, dict[str, Any]], dict[str, Any]]


def _handle_enumerate_subdomains(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → enumerate_subdomains tool function (spec §3.2 ①)."""
    from secagent.tools.enumerate_subdomains import enumerate_subdomains

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target_domain": args.get("target_domain", ""),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    sources = args.get("sources")
    if sources:
        params["sources"] = sources

    return enumerate_subdomains(
        gate=gate,
        params=params,
        authz_token=authz_token,
        caller_id=caller_id,
    )


_ENUMERATE_SUBDOMAINS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_domain": {
            "type": "string",
            "description": (
                "Root domain to enumerate subdomains for (e.g. 'acme.com'). "
                "Must be within the scope of the supplied authz_token."
            ),
        },
        "authz_token": {
            "type": "string",
            "description": (
                "Authorization token issued via `secagent authz add` and "
                "verified via `secagent authz verify`. The token's scope must "
                "cover target_domain; otherwise NOT_AUTHORIZED is returned."
            ),
        },
        "sources": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Optional list of subfinder passive sources (e.g. "
                "['crtsh','virustotal']). Defaults to subfinder's full source set."
            ),
        },
        "timeout_sec": {
            "type": "integer",
            "default": 120,
            "description": "Subprocess timeout in seconds.",
        },
        "caller_id": {
            "type": "string",
            "description": (
                "Optional caller identifier written to the audit log. "
                "Defaults to 'mcp-client'."
            ),
        },
    },
    "required": ["target_domain", "authz_token"],
}


def all_tools() -> list[ToolDefinition]:
    """Return every tool currently exposed over MCP.

    M2b ships only `enumerate_subdomains`. M3 will append probe_services,
    crawl_target, gather_osint, scan_secret_leaks, scan_vulnerabilities here.
    """
    return [
        ToolDefinition(
            name="enumerate_subdomains",
            description=(
                "Enumerate subdomains of an authorized domain using subfinder "
                "(passive sources only, read-only — no packets sent to the "
                "target). Returns unified Finding objects of type 'subdomain'."
            ),
            input_schema=_ENUMERATE_SUBDOMAINS_SCHEMA,
            handler=_handle_enumerate_subdomains,
        ),
    ]
