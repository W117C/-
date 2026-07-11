# SecAgent

Security MCP server — wraps open-source security tools (subfinder/httpx/nuclei/naabu/ffuf/katana/dnsx/tlsx/uncover/gitleaks) + custom reverse engineering analyzers into a unified compliance-gated interface for any MCP-compatible agent (Claude Code, Codex, etc.).

> **Status:** Production-ready. 15 MCP tools, 6 binary tools, 13320 Nuclei templates, 661 tests.

See [`secagent/README.md`](secagent/README.md) for the full documentation.

## Quick start

```bash
cd secagent
make install                    # pip deps + binary tools + Nuclei templates
make health-check               # verify everything is ready
secagent authz add --domain example.com
secagent authz verify <token> --method dns_txt
python -m secagent.server       # stdio MCP server
```

## Repository structure

| Path | Description |
|------|-------------|
| [`secagent/`](secagent/) | Main project — Python package, MCP server, tools |
| [`secagent/src/secagent/`](secagent/src/secagent/) | Source code |
| [`secagent/tests/`](secagent/tests/) | Test suite (661 tests) |
| [`secagent/docs/`](secagent/docs/) | Documentation |
| [`secagent/bin/`](secagent/bin/) | Binary tools (subfinder, httpx, nuclei, etc.) |
