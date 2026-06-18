"""SecAgent MCP server — stdio transport entry point.

Run with:
    python -m secagent.server

Requires the optional `mcp` dependency:
    pip install -e ".[mcp]"

The MCP SDK is imported lazily so that importing this module without the SDK
installed still produces a clear error message instead of an ImportError
traceback. All dispatch logic lives in `SecAgentServer` (no SDK coupling),
so this file is just thin transport glue.
"""
from __future__ import annotations

import asyncio
import json
import sys


def _import_mcp():
    try:
        # mcp SDK ≥1.x moved Server into mcp.server; types stays at mcp.types.
        from mcp.server import Server
        from mcp import types
        import mcp.server.stdio
    except ImportError as exc:
        sys.stderr.write(
            f"ERROR: MCP SDK not installed. Install with: pip install -e '.[mcp]'\n"
            f"  (underlying error: {exc})\n"
        )
        sys.exit(1)
    return Server, types, mcp.server.stdio


async def _run() -> None:
    Server, types, stdio = _import_mcp()

    # Imported after the SDK check so a missing SDK does not block importing
    # the rest of the package during `python -c "import secagent"`.
    from secagent.server.app import SecAgentServer

    server = Server("secagent")
    app = SecAgentServer()

    @server.list_tools()
    async def handle_list_tools():  # type: ignore[no-untyped-def]
        return [
            types.Tool(
                name=td.name,
                description=td.description,
                inputSchema=td.input_schema,
            )
            for td in app.list_tools()
        ]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict):  # type: ignore[no-untyped-def]
        result = app.call_tool(name, arguments or {})
        text = json.dumps(result, indent=2, default=str, ensure_ascii=False)
        return [types.TextContent(type="text", text=text)]

    async with stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def main() -> None:
    """Console-script entry point (`secagent-server` once installed)."""
    asyncio.run(_run())


if __name__ == "__main__":
    main()
