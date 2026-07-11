# SecAgent

Security MCP server — wraps open-source security tools (subfinder/httpx/nuclei/naabu/ffuf/katana/dnsx/tlsx/uncover/gitleaks) + custom reverse engineering analyzers into a unified compliance-gated interface for any MCP-compatible agent (Claude Code, Codex, etc.).

> **Status:** Production-ready. 15 MCP tools, 6 binary tools, 13320 Nuclei templates, 661 tests.

## Quick start

```bash
cd secagent
make install                    # pip deps + binary tools + Nuclei templates
make health-check               # verify everything is ready
secagent authz add --domain example.com
secagent authz verify <token> --method dns_txt
python -m secagent.server       # stdio MCP server
```

See [`docs/QUICKSTART.md`](docs/QUICKSTART.md) for the full 5-minute onboarding flow.

## Tools (15 MCP)

### Scan & Reconnaissance

| Tool | Adapter | Risk |
|------|---------|------|
| `enumerate_subdomains` | SubfinderAdapter → subfinder | read-only |
| `scan_secret_leaks` | GitleaksAdapter → gitleaks | read (secrets redacted) |
| `crawl_target` | SimpleCrawlerAdapter (stdlib) | read (HTTP GET) |
| `passive_recon` | TheHarvesterAdapter → theHarvester | read-only |
| `check_health` | diagnostic | none |
| `crawl_with_katana` | KatanaAdapter → katana | read (HTTP GET) |
| `resolve_dns` | DnsxAdapter → dnsx | read-only |
| `fingerprint_tls` | TlsxAdapter → tlsx | read-only |
| `search_engines` | UncoverAdapter (Shodan/Censys/Fofa) | read (public data) |

### Active Probing

| Tool | Adapter | Risk |
|------|---------|------|
| `scan_ports` | NaabuAdapter → naabu | active probe |
| `probe_services` | HttpxAdapter → httpx | read (HTTP GET) |
| `discover_paths` | FfufAdapter → ffuf | active probe |
| `scan_vulnerabilities` | NucleiAdapter → nuclei | **active probes** (3-layer guard) |
| `attack_surface_scan` | orchestration (chains 7 phases) | mixed |
| `web_vuln_scan` | WebVulnAdapter (SQLi/XSS/SSRF/LFI/IDOR/XXE) | **active probes** |

### Reverse Engineering

| Tool | Capability |
|------|-----------|
| `decode_value` | auto-detect & decode base64/hex/URL/JWT/timestamps/hash |
| `analyze_web` | JS deobfuscation, WAF fingerprinting, URL param analysis |
| `inspect_token` | JWT decode, cookie analysis, token security assessment |
| `analyze_binary` | PE/ELF/Mach-O structure, disassembly, string extraction, packing detection |

## Compliance

Every tool passes through a 4-line defense:

1. **Authorization** — token verified + target in scope
2. **Blocklist** — gov TLDs, private IPs, custom domains
3. **Data minimization** — secrets redacted before storage
4. **Audit log** — append-only, hash-chained

`scan_vulnerabilities` adds two extra layers (blocklist re-check per target + rate-limit clamp).

## Tests

```bash
make test
# 661 tests pass
```

## Docs

- [`docs/QUICKSTART.md`](docs/QUICKSTART.md) — 5-minute install → scan → report
- [`docs/MCP_SERVER.md`](docs/MCP_SERVER.md) — MCP server wiring, tool contract
- [`docs/AUTHORIZATION.md`](docs/AUTHORIZATION.md) — authorization scope + ownership proof
- [`docs/COMPLIANCE.md`](docs/COMPLIANCE.md) — 4 defense lines
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — full architecture, layer diagram, extension guide
