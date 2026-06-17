# SecAgent

Security MCP server that wraps **SuperSpider** + open-source tooling
(Nuclei/Subfinder/httpx/gitleaks/theHarvester) into tools callable by
Codex / Claude Code / Reasonix.

> **Status:** M1 — compliance skeleton. No tools connected yet. Tool adapters
> arrive in M2+.

## What M1 provides

The 4-line compliance defense, runnable independently:
- **Defense line 1** — authorization registry (scope + verified token)
- **Defense line 2** — blocklist (gov TLDs, private IPs, custom domains)
- **Defense line 3** — data minimization (schema + retention hooks)
- **Defense line 4** — append-only, hash-chained audit log

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
```
