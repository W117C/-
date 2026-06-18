# SecAgent MCP Server

SecAgent exposes its security tools to MCP-compatible agents (Claude Code,
Codex, Reasonix, …) over the Model Context Protocol. Every tool call flows
through the four compliance defense lines (authorization → blocklist → audit
→ quota), so an agent can only act on targets the operator has explicitly
authorized.

> **Status (M2b):** the MCP stdio server is live with one tool —
> `enumerate_subdomains`. Five more tools (probe_services, crawl_target,
> gather_osint, scan_secret_leaks, scan_vulnerabilities) arrive in M3.

---

## 1. Install

SecAgent requires Python ≥ 3.10 for the MCP server (the `mcp` SDK needs it).
Install with the `mcp` extra:

```bash
cd secagent
pip install -e ".[mcp]"
```

Verify:

```bash
python -m secagent.server --help   # or just import-check:
python -c "import mcp; print('mcp ok')"
```

You also need the `subfinder` binary on disk (M2a wraps it). For now, place it
at `./bin/subfinder` manually — the automated installer arrives in M4. See
`src/secagent/binmgmt/versions.py` for the pinned version.

## 2. Register an authorization scope (once per target)

Authorization is done on the CLI, **never** exposed as an MCP tool — this is
defense line 1. The agent only ever receives a token; it cannot mint one.

```bash
# Issue a token for acme.com (includes *.acme.com)
secagent authz add --domain acme.com --note "customer onboarding"
# => token: auth_abc123...

# Prove ownership (DNS TXT / file / cert), then mark verified.
# DNS TXT:  _scan-verify.acme.com  TXT="verify=auth_abc123..."
secagent authz verify auth_abc123... --method dns_txt

# Confirm
secagent authz list
```

Only **verified** tokens can drive tools. Unverified tokens are refused with
`NOT_AUTHORIZED` — this is intentional (spec §4.1).

## 3. Wire the server into your MCP client

### Claude Code / Codex / Reasonix (stdio)

Add SecAgent to your client's MCP config (for Claude Code, edit
`~/.config/claude-code/config.json` or the project's `.mcp.json`):

```json
{
  "mcpServers": {
    "secagent": {
      "command": "python",
      "args": ["-m", "secagent.server"],
      "env": {
        "SECAGENT_DB_PATH": "/absolute/path/to/secagent.db"
      }
    }
  }
}
```

Environment variables (override `config.yaml`, see `config.example.yaml`):

| Variable | Purpose |
| --- | --- |
| `SECAGENT_DB_PATH` | SQLite database path (authorizations, audit log, quota) |
| `SECAGENT_DEFAULT_QUOTA` | Default quota per token (default: 100) |

The server reads the same DB the CLI writes to, so tokens issued via
`secagent authz add` are immediately usable by the agent.

## 4. Use it from the agent

Once connected, ask the agent in natural language:

> "Find all subdomains of acme.com using my authz token auth_abc123..."

The agent will call the `enumerate_subdomains` tool with:

```json
{
  "target_domain": "acme.com",
  "authz_token": "auth_abc123..."
}
```

### Success response (unified output, spec §3.1)

```json
{
  "engagement_id": "eng_9f2a1b3c",
  "tool": "enumerate_subdomains",
  "findings": [
    {
      "id": "fnd_...",
      "type": "subdomain",
      "severity": "info",
      "target": "sub.acme.com",
      "title": "Subdomain: sub.acme.com",
      "evidence": { "source": "crtsh", "domain_queried": "acme.com" },
      "source_tool": "subfinder",
      "timestamp": "2026-06-18T14:30:00+00:00"
    }
  ],
  "summary": { "total": 1, "by_severity": { "info": 1 }, "by_type": { "subdomain": 1 } },
  "quota_used": 1
}
```

### Error responses (unified error model, spec §3.1)

Every failure is returned as tool output (not raised), so the agent can reason
about retrying:

| `code` | Meaning | `retryable` |
| --- | --- | --- |
| `NOT_AUTHORIZED` | Target outside token scope, or token unverified/unknown | false |
| `COMPLIANCE_BLOCK` | Target hit the absolute blocklist (.gov/.mil/private IPs/…) | false |
| `RATE_LIMITED` | Quota exhausted | true |
| `TOOL_TIMEOUT` | Subprocess exceeded `timeout_sec` | true |
| `TOOL_FAILED` | Underlying binary crashed / not installed | true |
| `INVALID_INPUT` | Missing required argument or unknown tool | false |

## 5. Architecture (why dispatch is testable without the MCP SDK)

```
                 ┌──────────────────────────────────┐
   MCP client ──▶│  server/__main__.py              │  stdio transport
                 │  (imports `mcp` SDK lazily)       │  thin glue only
                 └───────────────┬──────────────────┘
                                 │ app.call_tool / app.list_tools
                                 ▼
                 ┌──────────────────────────────────┐
                 │  server/app.py  SecAgentServer   │  NO mcp SDK dep
                 │  • Config → store → gate         │  fully unit-tested
                 │  • tool dispatch + error mapping │  (tests/test_server_app.py)
                 └───────────────┬──────────────────┘
                                 │ handler(gate, args)
                                 ▼
                 ┌──────────────────────────────────┐
                 │  server/tools_registry.py        │  declarative tool table
                 │  → secagent/tools/*              │  (M1 gate + M2a adapters)
                 └──────────────────────────────────┘
```

Adding a tool in M3 = one new `ToolDefinition` in `tools_registry.py` + the
existing tool function. `app.py` and `__main__.py` do not change.

## 6. Troubleshooting

- **`ERROR: MCP SDK not installed`** — run `pip install -e ".[mcp]"`.
- **`NOT_AUTHORIZED` for a target you own** — did you run
  `secagent authz verify` after `authz add`? Unverified tokens always refuse.
- **`TOOL_FAILED: binary not found`** — place `subfinder` at `./bin/subfinder`
  (or the path in `config.yaml` → `tools.binaries_dir`). The M4 installer will
  automate this.
- **Agent sees no tools** — confirm the client config's `command`/`args` resolve
  to the same Python that has `secagent[mcp]` installed. `which python` inside
  the client's environment should point at your venv.
