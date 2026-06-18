# SecAgent

Security MCP server that wraps **SuperSpider** + open-source tooling
(Nuclei/Subfinder/httpx/gitleaks/theHarvester) into tools callable by
Codex / Claude Code / Reasonix.

> **Status:** M3 — all 6 MCP tools live. Next: M4 (install script, reports,
> 5-minute onboarding polish).

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

## M3 — Remaining 5 Tools

All six atomic tools are now wired through the compliance gate:

| Tool | Adapter | Underlying | Finding type | Risk |
|---|---|---|---|---|
| `enumerate_subdomains` | SubfinderAdapter | subfinder | subdomain | read-only |
| `probe_services` | HttpxAdapter | httpx | service | read (HTTP GET) |
| `gather_osint` | TheHarvesterAdapter | theHarvester | intel | read (public data) |
| `scan_secret_leaks` | GitleaksAdapter | gitleaks | secret_leak | read (secrets **redacted**) |
| `crawl_target` | SimpleCrawlerAdapter | built-in stdlib | exposure | read (HTTP GET) |
| `scan_vulnerabilities` | NucleiAdapter | nuclei | vulnerability | **active probes** |

### `scan_vulnerabilities` — three-layer compliance guard (spec §3.2 ③)

Because nuclei sends active probe packets (highest legal risk), this tool
adds two extra defense layers on top of the standard gate:

1. **Layer 1 — gate.check per target** (authz + blocklist + audit), evaluated
   on the hostname so URL targets work.
2. **Layer 2 — blocklist re-check** immediately before nuclei runs. Even if
   a future bug let a `.gov` / private-IP slip through layer 1, this second
   pass refuses it. One blocked target refuses the whole call.
3. **Layer 3 — rate-limit clamp** (`-rate-limit`), clamped to `[1, 500]` so a
   caller cannot accidentally DoS their own asset.

### `scan_secret_leaks` — data minimization (spec §4.3)

Secrets are **redacted** before they ever reach a Finding: only the first 4
and last 4 characters are kept (`AKIA****MPLE`). The raw `Secret` / `Match`
fields from gitleaks are never stored. Tests assert the full plaintext does
not appear anywhere in tool output.

### `crawl_target` — built-in crawler (MVP decision)

Spec called for pyspider, but this repo has no pyspider code (only docs).
MVP ships a pure-stdlib static crawler (`urllib` + regex extractors for
forms / JS endpoints / emails / suspicious comments). Swappable for pyspider
in a later milestone without touching the tool function.

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
# 175 tests pass (M1 compliance + M2a subfinder + M2b MCP server + M3 five tools)
```

The server application core (`server/app.py`) is tested without the MCP SDK;
only running the live stdio server requires `pip install -e ".[mcp]"`.
