# SecAgent

Security MCP server that wraps **SuperSpider** + open-source tooling
(Nuclei/Subfinder/httpx/gitleaks/theHarvester) into tools callable by
Codex / Claude Code / Reasonix.

> **Status:** M4 — install script + report generator + docs. MVP complete.
> 6 tools live, 226 tests passing. Ready for design-partner feedback.

## Quick install

```bash
cd secagent
pip install -e ".[mcp]"          # Python ≥3.10 required by the mcp SDK
bash scripts/install.sh          # downloads subfinder/httpx/nuclei/gitleaks
pip install theHarvester         # OSINT tool (Python package, not a binary)
```

For the full 5-minute onboarding flow (install → authorize → scan → report),
see [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

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

## M4 — Install + Reports + Docs

### One-command binary install

`scripts/install.sh` (backed by `secagent.binmgmt.installer`) downloads the
4 Go binaries pinned in `versions.py`, verifies SHA-256 checksums (skips
with a warning while checksums are placeholders), extracts, and marks them
executable. Detects macOS/Linux × amd64/arm64 automatically.

```bash
bash scripts/install.sh              # install all 4
python -m secagent.binmgmt.installer --tool nuclei  # install one
```

### Report generation

`secagent.report` turns tool-call result dicts into human-readable reports:

```python
from secagent.report import render_markdown, render_json

# engagements = list of tool-call return dicts
open("report.md", "w").write(render_markdown(engagements))
open("report.json", "w").write(render_json(engagements))
```

The Markdown report includes a cross-engagement severity summary, per-tool
detail sections ordered critical → info, and full evidence for each finding.
JSON report is a structured document with `report_metadata`, aggregated
`summary`, and the raw `engagements` array.

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
# 226 tests pass (M1 + M2a + M2b + M3 + M4 installer + report)
```

The server application core (`server/app.py`) is tested without the MCP SDK;
only running the live stdio server requires `pip install -e ".[mcp]"`.

## Docs

- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) — 5-minute install → scan → report
- [`docs/MCP_SERVER.md`](docs/MCP_SERVER.md) — MCP server wiring, tool contract, troubleshooting
- [`docs/AUTHORIZATION.md`](docs/AUTHORIZATION.md) — authorization scope + ownership proof
- [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) — 4 defense lines
- [`../docs/superpowers/specs/2026-06-16-secagent-mcp-design.md`](../docs/superpowers/specs/2026-06-16-secagent-mcp-design.md) — full design spec
