# Quickstart — 5 minutes to your first scan

This guide takes you from zero to a completed security scan in under five
minutes, assuming you have Python 3.10+ and network access.

## Step 1 — Install (60 seconds)

```bash
git clone <this-repo> && cd 爬虫/secagent
pip install -e ".[mcp]"

# Download the 4 tool binaries (subfinder, httpx, nuclei, gitleaks)
bash scripts/install.sh
```

The install script detects your OS/arch, downloads the pinned binary
versions, verifies checksums (skips with a warning if the checksum is still
a placeholder), extracts, and marks them executable. theHarvester is a
Python package — install it separately:

```bash
pip install theHarvester
```

Verify everything is in place:

```bash
secagent --help              # CLI works
./bin/subfinder -version     # binary downloaded
python -c "import mcp; print('mcp ok')"  # MCP SDK present
```

## Step 2 — Register an authorization scope (60 seconds)

SecAgent **never** scans a target you haven't proven you own. This is
defense line 1 (spec §4.1) and it is non-negotiable.

```bash
# Issue a token for a domain you own
secagent authz add --domain yourdomain.com --note "my first scan"
# => token: auth_AbCdEf1234...

# Prove ownership. Pick one:
#   DNS TXT:  _scan-verify.yourdomain.com  TXT="verify=auth_AbCdEf1234..."
#   File:     https://yourdomain.com/.well-known/scan-auth  contains the token
#
# Then mark verified:
secagent authz verify auth_AbCdEf1234... --method dns_txt

# Confirm
secagent authz list
#   auth_AbCdEf1234...  domain=yourdomain.com  verified=yes
```

Only **verified** tokens can drive tools. An unverified token returns
`NOT_AUTHORIZED` on every call — this is by design.

## Step 3 — Connect to Claude Code (or any MCP client) (60 seconds)

Edit `~/.config/claude-code/config.json` (or your client's MCP config):

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

Restart Claude Code. You should see `secagent` tools appear.

## Step 4 — Run your first scan (60 seconds)

In Claude Code, just ask in natural language:

> I have authz token auth_AbCdEf1234... for yourdomain.com.
> Find all its subdomains, then probe which ones are live HTTP services.

The agent will orchestrate the calls:

```
1. enumerate_subdomains(yourdomain.com)  → 23 subdomains
2. probe_services([23 subdomains])       → 11 live services
```

Every call flows through the four compliance defense lines:

| Line | What it does | When |
|---|---|---|
| 1 · Authorization | Token verified + target in scope | Before every tool |
| 2 · Blocklist | .gov/.mil/private IPs refused | Before every tool |
| 3 · Data minimization | Secrets redacted, TTL retention | In findings storage |
| 4 · Audit | Hash-chained, append-only log | Every call (pass or refuse) |

## Step 5 — Generate a report (30 seconds)

The agent's tool output is already structured JSON. To produce a
human-readable report, pipe engagement results through the report module:

```python
from secagent.report import render_markdown, render_json

# `engagements` is a list of tool-call result dicts
print(render_markdown(engagements))
# or save:
open("scan-report.md", "w").write(render_markdown(engagements))
open("scan-report.json", "w").write(render_json(engagements))
```

The Markdown report includes a severity summary table, per-engagement
detail sections ordered critical → info, and full evidence for each finding.

## You're done

That's the whole MVP loop: **install → authorize → scan → report**.

### What's intentionally NOT in the MVP

- Web console (CLI only)
- Scheduled / continuous monitoring (manual trigger only)
- Email/Slack alerts
- Multi-user / RBAC
- Hosted service (local only)
- REST API (MCP only)

These are Team-version features (spec §8). The MVP proves the
agent-driven scan loop works end to end.

### Troubleshooting

| Symptom | Fix |
|---|---|
| `TOOL_FAILED: binary not found` | Run `bash scripts/install.sh`; confirm `./bin/` has the 4 binaries |
| `NOT_AUTHORIZED` on your own domain | Did you run `secagent authz verify` after `authz add`? |
| `COMPLIANCE_BLOCK` | Target hit the absolute blocklist (.gov/.mil/private IP). These are never scanned, even if authorized. |
| Claude Code shows no secagent tools | Confirm `python -m secagent.server` runs without error; check the `command`/`args` in your MCP config resolve to the right Python |
| `mcp` ImportError | `pip install -e ".[mcp]"` (the `[mcp]` extra) |

See [`docs/MCP_SERVER.md`](MCP_SERVER.md) for the full tool contract and
[`docs/AUTHORIZATION.md`](AUTHORIZATION.md) for authorization details.
