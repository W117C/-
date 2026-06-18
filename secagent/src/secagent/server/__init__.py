"""MCP server layer — exposes SecAgent tools over the Model Context Protocol.

Architecture (M2b):
  - `app.py`          — `SecAgentServer` application core (no MCP SDK dependency,
                        fully unit-testable). Loads config, constructs the
                        compliance gate, dispatches tool calls, maps errors.
  - `tools_registry.py` — declarative tool definitions (schema + handler).
                        Adding a new tool = appending one entry here.
  - `__main__.py`     — stdio transport adapter. Thin glue that imports the
                        optional `mcp` SDK and delegates to `SecAgentServer`.

Design rationale: keeping the SDK out of `app.py` means M1's compliance gate,
M2a's tool functions, and M2b's dispatch logic all stay testable in one
pytest run without installing the MCP SDK. The SDK is only needed to actually
serve an MCP client.
"""
from secagent.server.app import SecAgentServer, ToolDefinition

__all__ = ["SecAgentServer", "ToolDefinition"]
