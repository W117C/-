# SecAgent

Security MCP server that wraps **SuperSpider** + open-source tooling
(Nuclei/Subfinder/httpx/gitleaks/theHarvester) into tools callable by
Codex / Claude Code / Reasonix.

> **Status:** M2b — MCP stdio server live with `enumerate_subdomains`.
> Next: M3 adds the remaining 5 tools (httpx/nuclei/gitleaks/theHarvester/pyspider).

## What M1 provides

The 4-line compliance defense, runnable independently:
- **Defense line 1** — authorization registry (scope + verified token)
- **Defense line 2** — blocklist (gov TLDs, private IPs, custom domains)
- **Defense line 3** — data minimization (schema + retention hooks)
- **Defense line 4** — append-only, hash-chained audit log

## M2a — Subfinder Adapter

The first tool is wired end-to-end:

- **`enumerate_subdomains`** — calls subfinder via subprocess adapter,
  parses JSON output into unified Findings, passes through compliance gate
  (auth + blocklist + audit + quota).

The tool function (`secagent/tools/enumerate_subdomains.py`) is the boundary
between the adapter layer and the future MCP server. It can be called
directly in tests without MCP.

## M2b — MCP Server

The MCP stdio server is live. An MCP-compatible agent (Claude Code / Codex /
Reasonix) can now drive `enumerate_subdomains` through the four compliance
defense lines end-to-end.

- **`secagent.server`** — `SecAgentServer` application core (no MCP SDK
  dependency, fully unit-tested) + stdio transport adapter in `__main__.py`.
- Dispatch + unified error mapping (`NOT_AUTHORIZED` / `COMPLIANCE_BLOCK` /
  `TOOL_FAILED` / …) all live in `app.py`, so the SDK stays thin glue.
- Adding a tool in M3 = one entry in `server/tools_registry.py`.

### Install + run

```bash
cd secagent
pip install -e ".[mcp]"          # Python ≥3.10 required by the mcp SDK
secagent authz add --domain acme.com
secagent authz verify <token> --method dns_txt
python -m secagent.server        # stdio MCP server
```

See [`docs/MCP_SERVER.md`](docs/MCP_SERVER.md) for client wiring (Claude Code
config JSON), the full request/response contract, and troubleshooting.

## Install (dev)

```bash
cd secagent
pip install -e ".[dev]"
```

## Use the CLI

```bash
# Register an authorization scope, get a token
secagent authz add --domain acme.com --note "customer onboarding"
# => token: auth_xxx

# Prove ownership (DNS TXT / file / cert), then mark verified
secagent authz verify auth_xxx --method dns_txt

# List authorizations
secagent authz list
```

## Design

See `../docs/superpowers/specs/2026-06-16-secagent-mcp-design.md`.

## Tests

```bash
cd secagent && pytest -v
# 80 tests pass (M1 compliance + M2a subfinder adapter + M2b MCP server core)
```

The server application core (`server/app.py`) is tested without the MCP SDK;
only running the live stdio server requires `pip install -e ".[mcp]"`.
