"""HackerOne bug-bounty workflow engine (MVP).

Usage:
    from secagent.workflow.hunterone import HackerOneWorkflow

    wf = HackerOneWorkflow(
        target="https://example.com",
        authz_token=None,       # or a registered token for active scans
        output_dir="./reports",
    )
    report = wf.run()  # returns path to generated report

Architecture (5-step pipeline):
  1. Architecture identification — SPA / MPA / RSC detection
  2. Endpoint discovery          — JS-extracted API endpoints
  3. Vulnerability scanning      — active verification (optional, needs token)
  4. Report generation           — HackerOne-format .md with adversary thinking
  5. Retrospective prompt        — knowledge-base archival guidance

References:
  - [[real-target-web-vuln-methodology]]  — 5-step methodology validated on live targets
  - [[secagent]]                          — toolchain capability bounds
"""

from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

log = logging.getLogger(__name__)

_SDK_AVAILABLE = False
try:
    from secagent.config import Config
    from secagent.core.gate import ComplianceGate
    from secagent.storage.sqlite_store import SQLiteStore
    _SDK_AVAILABLE = True
except ImportError:
    pass  # running standalone; fine for reconnaissance-only mode


# ── Data models ────────────────────────────────────────────────────────────

@dataclass
class Endpoint:
    """Discovered API endpoint."""
    url: str
    method: str = "GET"
    source: str = "manual"       # js / crawl / manual
    params: list[str] = field(default_factory=list)
    has_body: bool = False


@dataclass
class ArchitectureInfo:
    """Result of architecture identification step."""
    framework: str               # "spa" | "mpa" | "rsc" | "unknown"
    evidence: str                # how we determined it
    catch_all: bool = False      # does every path return same page?
    catch_all_hash: str = ""     # sha256 of catch-all response
    server_header: str = ""
    js_files: list[str] = field(default_factory=list)
    api_patterns: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Aggregated result of a vulnerability scan step."""
    module: str
    findings_count: int
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkflowResult:
    """Complete workflow output."""
    target: str
    started_at: str
    duration_sec: float
    architecture: ArchitectureInfo | None = None
    endpoints: list[Endpoint] = field(default_factory=list)
    scans: list[ScanResult] = field(default_factory=list)
    report_path: str = ""
    token_used: bool = False
    h1_username: str = ""
    bbp_profile: str = ""
    cookie: str = ""
    post_body_params: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ── Architecture identification ────────────────────────────────────────────

def _fetch(client: httpx.Client, url: str, *, allow_redirects: bool = True,
           timeout: float = 15) -> httpx.Response | None:
    """Fetch a URL with a safe timeout, returning None on transient failure."""
    try:
        return client.get(url, follow_redirects=allow_redirects, timeout=timeout)
    except httpx.RequestError as e:
        log.warning("Request to %s failed: %s", url, e)
        return None


def _hash_body(resp: httpx.Response) -> str:
    return hashlib.sha256(resp.content).hexdigest()[:16]


def _identify_architecture(target: str, *, timeout: float = 30) -> ArchitectureInfo:
    """Identify the web architecture of *target* with minimal HTTP probes.

    Strategy ([[real-target-web-vuln-methodology]] Step 1):
      1. Fetch /
      2. Fetch /random-string-that-should-not-exist
      3. Compare response hashes → detect catch-all
      4. Inspect HTML markers → SPA (empty shell) vs MPA vs RSC

    Returns an ArchitectureInfo with confidence evidence.
    """
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"
    random_path = f"{base}/__secagent_probe_{int(time.time())}"

    info = ArchitectureInfo(framework="unknown", evidence="")

    with httpx.Client(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": "Mozilla/5.0 (SecAgent H1 Workflow)"},
        verify=True,
    ) as client:
        root_resp = _fetch(client, target)
        random_resp = _fetch(client, random_path)

        if root_resp is None:
            info.evidence = "Target unreachable"
            return info

        info.server_header = root_resp.headers.get("Server", "")
        body = root_resp.text

        # ── Catch-all detection ──
        if random_resp is not None:
            root_hash = _hash_body(root_resp)
            random_hash = _hash_body(random_resp)
            if root_hash == random_hash and random_resp.status_code == 200:
                info.catch_all = True
                info.catch_all_hash = root_hash
                info.evidence = (
                    f"Catch-all detected: / and {random_path} both return "
                    f"200 with identical content (hash={root_hash})"
                )

        # ── Framework detection from HTML ──
        if re.search(r'<div\s+id=["\']__next["\']', body):
            info.framework = "rsc"  # Next.js App Router / RSC
            info.evidence += "; found __next div (Next.js App Router)"
        elif re.search(r'<div\s+id=["\']__NEXT_DATA__["\']', body):
            info.framework = "spa"  # Next.js pages router SPA
            info.evidence += "; found __NEXT_DATA__ (Next.js SPA)"
        elif re.search(r'<div\s+id=["\']root["\']|react-root', body):
            info.framework = "spa"  # generic React SPA
            info.evidence += "; found react root div"
        elif re.search(r'<div\s+id=["\']app["\']', body, re.IGNORECASE):
            info.framework = "spa"
            info.evidence += "; found app root div"
        elif "<html" in body[:200] and len(body) > 500:
            # Has substantial server-rendered HTML
            info.framework = "mpa"
            info.evidence += "; server-rendered HTML >500 bytes"

        # ── Extract JS files ──
        js_pattern = re.compile(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', re.IGNORECASE)
        info.js_files = [
            urljoin(base, m) if not m.startswith(("http:", "https:")) else m
            for m in js_pattern.findall(body)
        ]

        # ── Detect API patterns ──
        api_hints = set(re.findall(r'["\'](/api/[^\s"\'<>]+)', body))
        info.api_patterns = sorted(api_hints)[:20]

        if not info.evidence:
            info.evidence = f"status={root_resp.status_code}, content-length={len(body)}"

    return info


# ── Endpoint discovery ─────────────────────────────────────────────────────

def _extract_js_endpoints(client: httpx.Client, js_urls: list[str],
                          base_url: str, timeout: float = 15) -> list[Endpoint]:
    """Fetch referenced JS files and extract inline API endpoint patterns."""
    endpoints: list[Endpoint] = []
    seen: set[str] = set()

    # Patterns for JS-internal API routes
    route_patterns = [
        re.compile(r"""["']((?:/api/|/graphql|/v\d+/|/auth/|/oauth/)\S*?)["']"""),
        re.compile(r"""fetch\(["']((?:/api/|/graphql|/v\d+/)\S*?)["']"""),
        re.compile(r"""url:\s*["']((?:/api/|/graphql|/v\d+/)\S*?)["']"""),
        re.compile(r"""path:\s*["']((?:/api/|/graphql|/v\d+/)\S*?)["']"""),
        re.compile(r"""baseURL:\s*["'](\S*?)["']"""),
    ]

    for js_url in js_urls[:15]:  # limit to 15 JS files
        try:
            resp = _fetch(client, js_url, timeout=timeout)
            if resp is None or resp.status_code != 200:
                continue

            body = resp.text
            for pat in route_patterns:
                for m in pat.finditer(body):
                    raw = m.group(1).strip("'\"")
                    full_url = urljoin(base_url, raw)
                    if full_url not in seen and raw.startswith("/"):
                        seen.add(full_url)
                        endpoints.append(Endpoint(
                            url=full_url,
                            method="GET",
                            source="js",
                            params=_extract_params_from_url(raw),
                        ))
        except Exception as e:
            log.debug("Could not parse JS %s: %s", js_url, e)

    return endpoints


def _extract_params_from_url(url: str) -> list[str]:
    """Heuristically extract parameter names from URL patterns."""
    params = set()
    # Template-style: /api/user/{id} or /api/user/:id
    for m in re.finditer(r'[{:](\w+)[}:]', url):
        params.add(m.group(1))
    return sorted(params)


# ── Vulnerability scanning (activates with token) ──────────────────────────

def _run_vuln_scan(target: str, authz_token: str,
                    bbp_profile: str = "",
                    cookie: str = "",
                    post_body_params: list[str] | None = None) -> list[ScanResult]:
    """Run active vulnerability scan using SecAgent web_vuln_scan.

    Requires a registered authz_token.  Returns per-module scan results.
    bbp_profile adjusts rate limits and module selection (e.g. "tiktok"
    disables SSRF OOB and CSRF, lowers rate limit to 10 req/s).

    NOTE: This is a skeleton for future integration.  In MVP, users run scans
    via the MCP tool interface (mcp__secagent__web_vuln_scan) which properly
    handles gate/authz.  This function is here so the workflow pipeline has a
    clear extension point.
    """
    rate_limit = 30
    skip_modules: set[str] = set()

    if bbp_profile == "tiktok":
        rate_limit = 10
        skip_modules.add("ssrf")       # TikTok forbids custom OOB; use sheriff
        # CSRF module is not yet in the scan pipeline, but mark for future
        skip_modules.add("csrf")
    results: list[ScanResult] = []
    if not _SDK_AVAILABLE:
        return [ScanResult(module="web_vuln_scan", findings_count=0,
                           raw={"error": "secagent SDK not available"})]

    try:
        from secagent.config import Config
        from secagent.core.gate import ComplianceGate
        from secagent.core.quota import QuotaManager
        from secagent.storage.sqlite_store import SQLiteStore
        from secagent.tools.web_vuln_scan import web_vuln_scan

        config = Config.load()
        store = SQLiteStore(config.db_path)
        store.bootstrap()
        quota = QuotaManager(store=store, default_total=config.default_quota_per_token)
        gate = ComplianceGate(
            store=store,
            quota=quota,
            default_quota=config.default_quota_per_token,
        )

        modules = ["sqli", "xss", "ssrf"]
        active_modules = [m for m in modules if m not in skip_modules]
        if skip_modules:
            log.info("  • Skipped modules: %s", sorted(skip_modules))
        for mod in active_modules:
            try:
                outcome = web_vuln_scan(
                    gate=gate,
                    params={
                        "target": target,
                        "modules": [mod],
                        "timeout_sec": 60,
                        "rate_limit": rate_limit,
                        "cookie": cookie,
                        "post_body_params": post_body_params or [],
                    },
                    authz_token=authz_token,
                    caller_id="hunterone-workflow",
                )
                findings = outcome.get("findings", [])
                results.append(ScanResult(
                    module=mod,
                    findings_count=len(findings),
                    raw=outcome,
                ))
            except Exception as e:
                log.warning("Scan module %s failed: %s", mod, e)
                results.append(ScanResult(module=mod, findings_count=0,
                                          raw={"error": str(e)}))

        # Secret leaks: gitleaks requires a local repo path, not a domain.
        # For H1 recon this is a manual step — left as an extension point.
        try:
            parsed = urlparse(target)
            domain = parsed.netloc
            log.info("Gitleaks scan for domain %s — requires manual repo path", domain)
            results.append(ScanResult(
                module="secret_leaks",
                findings_count=0,
                raw={"note": "Skipped — Gitleaks expects repository path, not domain. "
                       "For HackerOne, manually run: gitleaks detect --source <repo>"},
            ))
        except Exception as e:
            log.warning("Secret leaks scan skipped: %s", e)

    except Exception as e:
        log.error("Vuln scan setup failed: %s", e)
        results.append(ScanResult(module="setup", findings_count=0,
                                  raw={"error": str(e)}))
    return results


# ── Report generation ──────────────────────────────────────────────────────

def _generate_report(result: WorkflowResult, output_dir: str) -> str:
    """Generate a HackerOne-compatible markdown report.

    The report follows the [[real-target-web-vuln-methodology]] framework,
    including adversary-thinking sections and a retrospective prompt.
    """
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d_%H%M%S")
    safe_name = re.sub(r'[^a-zA-Z0-9.-]', '_', urlparse(result.target).netloc)
    path = Path(output_dir) / f"h1_{safe_name}_{timestamp}.md"
    path.parent.mkdir(parents=True, exist_ok=True)

    arch = result.architecture
    lines = [
        f"# HackerOne Bug Bounty Report — {result.target}",
        "",
        f"**Generated**: {result.started_at}",
        f"**Duration**: {result.duration_sec:.1f}s",
        f"**Authz Token**: {'✅ used (active scan)' if result.token_used else '⚠️ not provided (recon only)'}",
        f"**H1 Username**: {result.h1_username}" if result.h1_username else "",
        f"**BBP Profile**: `{result.bbp_profile}`" if result.bbp_profile else "",
        f"**Cookie**: {'✅ injected' if result.cookie else '⚠️ none'}",
        f"**POST body fuzzing**: {'✅ enabled (' + str(len(result.post_body_params)) + ' params)' if result.post_body_params else '⚠️ disabled'}",
        "",
        "---",
        "",
        "## 1. Architecture Identification",
        "",
        f"- **Framework**: `{arch.framework}`" if arch else "- **Framework**: `unknown`",
        f"- **Server**: `{arch.server_header}`" if arch and arch.server_header else "",
        f"- **Catch-all**: {'⚠️ YES — every path returns 200 (SPA noise trap) [[real-target-web-vuln-methodology]]' if arch and arch.catch_all else '✅ NO — distinct error pages'}" if arch else "",
        f"- **Evidence**: {arch.evidence}" if arch else "",
        "",
        "### JS Files Extracted",
    ]

    if arch and arch.js_files:
        for js in arch.js_files[:30]:
            lines.append(f"- `{js}`")
    else:
        lines.append("- (none)")

    lines += [
        "",
        "### API Patterns Found in HTML",
    ]
    if arch and arch.api_patterns:
        for pat in arch.api_patterns:
            lines.append(f"- `{pat}`")
    else:
        lines.append("- (none)")

    lines += [
        "",
        "---",
        "",
        "## 2. Discovered Endpoints",
        "",
    ]

    if result.endpoints:
        lines.append("| Method | URL | Source | Parameters |")
        lines.append("|--------|-----|--------|------------|")
        for ep in result.endpoints:
            params_str = ", ".join(ep.params) if ep.params else "—"
            lines.append(f"| {ep.method} | `{ep.url}` | {ep.source} | {params_str} |")
    else:
        lines.append("No endpoints discovered via static JS analysis.")
        lines.append("")
        lines.append("> ⚠️ For SPA targets, run `crawl_with_katana(headless=True)` to discover")
        lines.append("> dynamic endpoints that only appear after JS rendering.")

    lines += [
        "",
        "---",
        "",
        "## 3. Vulnerability Scan Results",
        "",
    ]

    if result.scans:
        total_findings = sum(s.findings_count for s in result.scans)
        lines.append(f"**Total findings**: {total_findings}")
        lines.append("")
        for scan in result.scans:
            lines.append(f"### {scan.module}")
            lines.append(f"- Findings: {scan.findings_count}")
            if scan.raw.get("error"):
                lines.append(f"- Error: {scan.raw['error']}")
        lines.append("")
    else:
        lines.append("> ⚠️ No active scan performed (no authz token). Run:")
        lines.append("> ```bash")
        lines.append(f"> secagent hunterone workflow {result.target} --token YOUR_TOKEN")
        lines.append("> ```")

    # Adversary-thinking block ([[real-target-web-vuln-methodology]])
    lines += [
        "",
        "---",
        "",
        "## 4. Adversary Thinking (反方思考)",
        "",
        "> Every conclusion MUST have a counterpart argument.",
        "",
        "| Claim | Counterargument | Failure Condition |",
        "|-------|----------------|-------------------|",
    ]
    if arch and arch.framework == "spa":
        lines.append(
            '| "SPA catch-all = no injection" | '
            "API endpoints under `/api/` are served server-side, independent of SPA routing | "
            "If /api/ endpoints exist and accept user input"
        )
    if arch and arch.framework == "rsc":
        lines.append(
            '| "RSC auto-encodes XSS" | '
            "Client components using `dangerouslySetInnerHTML` can bypass | "
            "If future updates introduce dynamic client rendering"
        )
    lines.append(
        '| "This scan found nothing" | '
        "Scan only tested discovered GET endpoints; POST/JSON/headers/IDOR not tested | "
        "Undiscovered endpoints with different auth/signature requirements"
    )
    lines.append(
        f'| "Target appears secure" | '
        f"This is a snapshot of {timestamp}; new endpoints may not have same protections | "
        f"New API versions released without security review"
    )

    lines += [
        "",
        "---",
        "",
        "## 5. BBP Policy Compliance",
        "",
    ]
    if result.bbp_profile == "tiktok":
        lines += [
            "> **Profile**: TikTok BBP (--bbp tiktok)",
            "",
            "This report has been filtered to comply with TikTok's Bug Bounty Program policy:",
            "",
            "| Policy Rule | Status |",
            "|-------------|--------|",
            "| SSRF: Only `ssrf-bait.byted.org` sheriff (no custom OOB) | ✅ Enforced — SSRF OOB auto-mode disabled |",
            "| Rate limit conservative (≤10 req/s) | ✅ Enforced — scan rate limited |",
            "| No CSRF testing (not accepted since 2023-07-05) | ✅ Excluded from scan modules |",
            "| No TikTok Partner API IDOR (not accepted since 2024-03-13) | ✅ Excluded from scan modules |",
            "| No TikTok One / Business Center access control (not accepted since 2024-12-16) | ✅ Excluded |",
            "| No internal resource enumeration | ✅ Target restricted to scope domains |",
            "| No DoS or service disruption | ✅ Recon-only or limited scan rate |",
            "",
            "### SSRF Sheriff Usage",
            "",
            "If SSRF testing is required, use the sheriff endpoint **outside this workflow**:",
            "```",
            "https://ssrf-bait.byted.org/full-read-ssrf          # Blind SSRF with flag",
            "https://ssrf-bait.byted.org/blind-ssrf/YOUR_FLAG    # Verification",
            "```",
            "Verification: `https://sf-ssrf-sheriff.tiktokcdn.com/obj/ssrf-detector-us/FLAG`",
            "",
            "> [!NOTE]",
            "> This workflow does NOT send SSRF payloads to TikTok targets.",
            "> Manual SSRF testing must use the provided sheriff endpoints only.",
            "",
            "### Known Exclusions Applied",
            "",
            "The following issue types are **not accepted** by TikTok BBP and have been skipped:",
            "- CSRF (all TikTok products, excluded since 2023-07-05)",
            "- IDOR / access control on TikTok Partner Shop API (excluded since 2024-03-13)",
            "- Access control / privilege escalation on TikTok One / Business Center (excluded since 2024-12-16)",
            "",
        ]
    else:
        lines += [
            "> No BBP profile specified. Run with `--bbp tiktok` for TikTok-specific",
            "> policy compliance (SSRF sheriff, rate limits, exclusions).",
            "",
        ]

    lines += [
        "",
        "---",
        "",
        "## 6. Retrospective / Knowledge Archival (复盘归档)",
        "",
        "> Archive this report to your knowledge base:",
        ">",
        "> ```bash",
        "> # Create a wiki page from this report",
        "> python3 /Users/ze/Downloads/知识库/scripts/wiki_create.py \\",
        f">   --title \"H1 Recon: {safe_name}\" \\",
        ">   --type archive \\",
        ">   --tags \"[hackerone, recon, bug-bounty]\" \\",
        f">   --file \"{path}\"",
        "> ```",
        "",
        "### Questions to answer in your retrospective",
        "",
        "- [ ] What did I miss in architecture identification? (check [[real-target-web-vuln-methodology]] checklist)",
        "- [ ] Were there endpoints I should have tested but didn't? (POST params, Content-Type confusion)",
        "- [ ] Did the catch-all detection save me time vs manually probing each path?",
        "- [ ] What should I add to SecAgent to avoid repeating this manual step?",
        "- [ ] Which finding would I submit to HackerOne, and how would I write the vulnerability title?",
        "",
        "---",
        "",
        "*Report generated by SecAgent hunterone workflow v0.1.0*",
        "*Methodology: [[real-target-web-vuln-methodology]] | Toolchain: [[secagent]]*",
    ]

    body = "\n".join(lines)
    path.write_text(body, encoding="utf-8")
    return str(path)


# ── Main workflow class ────────────────────────────────────────────────────

class HackerOneWorkflow:
    """Orchestrate the 5-step HackerOne bug-bounty workflow.

    Parameters
    ----------
    target : str
        Base URL of the target application.
    authz_token : str | None
        A pre-registered SecAgent authz token for active vulnerability scans.
        If None, only reconnaissance (steps 1–4) is performed.
    output_dir : str
        Directory for generated reports.

    Example
    -------
    >>> wf = HackerOneWorkflow("https://example.com")
    >>> report = wf.run()
    >>> print(f"Report: {report}")
    """

    def __init__(self, target: str, authz_token: str | None = None,
                 output_dir: str = "./reports",
                 bbp_profile: str | None = None,
                 h1_username: str | None = None,
                 cookie: str = "",
                 post_body_params: list[str] | None = None):
        self.target = target.rstrip("/")
        self.authz_token = authz_token
        self.output_dir = output_dir
        self.bbp_profile = bbp_profile or ""
        self.h1_username = h1_username or ""
        self.cookie = cookie
        self.post_body_params = post_body_params or []

    def run(self) -> str:
        """Execute the full workflow pipeline and return the report path."""
        result = WorkflowResult(
            target=self.target,
            started_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            duration_sec=0,
            token_used=self.authz_token is not None,
            h1_username=self.h1_username,
            bbp_profile=self.bbp_profile,
            cookie=self.cookie,
            post_body_params=self.post_body_params,
        )
        t0 = time.monotonic()

        # ── BBP Profile warnings ──
        if self.bbp_profile == "tiktok":
            log.info("  • BBP profile: TikTok — applying policy rules")
            if not self.h1_username:
                log.warning("  ⚠️ --h1-username not set! TikTok requires H1 username in reports.")
                result.errors.append(
                    "⚠️ TikTok BBP requires H1 username in report files. "
                    "Re-run with: --h1-username YOUR_USERNAME"
                )

        # ── Step 1: Architecture identification ──
        log.info("[1/5] Identifying architecture for %s", self.target)
        result.architecture = _identify_architecture(self.target)

        arch = result.architecture
        log.info("  • framework=%s catch_all=%s evidence=%s",
                 arch.framework, arch.catch_all, arch.evidence[:80])

        # Warn if SPA catch-all — user should not spend time on this
        if arch.catch_all and arch.framework == "spa":
            result.errors.append(
                "⚠️ SPA catch-all detected. Most paths return identical 200. "
                "Focus on /api/ endpoints and JS-rendered routes. "
                "See [[real-target-web-vuln-methodology]] Step 3."
            )
            log.warning(result.errors[-1])

        # ── Step 2: Endpoint discovery ──
        log.info("[2/5] Discovering endpoints from %d JS files", len(arch.js_files))
        with httpx.Client(
            timeout=httpx.Timeout(20),
            headers={"User-Agent": "Mozilla/5.0 (SecAgent H1 Workflow)"},
        ) as client:
            result.endpoints = _extract_js_endpoints(
                client, arch.js_files, self.target
            )
        log.info("  • %d endpoints discovered", len(result.endpoints))

        # ── Step 3: Vulnerability scan (only if token provided) ──
        if self.authz_token:
            log.info("[3/5] Running active vulnerability scan with token")
            if self.cookie:
                log.info("  • Using cookie: %s ...", self.cookie[:30])
            if self.post_body_params:
                log.info("  • POST body fuzzing: %d params", len(self.post_body_params))
            result.scans = _run_vuln_scan(self.target, self.authz_token,
                                          bbp_profile=self.bbp_profile,
                                          cookie=self.cookie,
                                          post_body_params=self.post_body_params)
            total = sum(s.findings_count for s in result.scans)
            log.info("  • %d total findings across %d modules",
                     total, len(result.scans))
        else:
            log.info("[3/5] Skipped — no authz token (recon-only mode)")

        # ── Step 4: Report generation ──
        log.info("[4/5] Generating HackerOne report")
        result.report_path = _generate_report(result, self.output_dir)
        log.info("  • %s", result.report_path)

        # ── Step 5: Summary ──
        result.duration_sec = round(time.monotonic() - t0, 1)
        log.info("[5/5] Done in %.1fs — report: %s",
                 result.duration_sec, result.report_path)

        # Print errors
        for err in result.errors:
            log.warning(err)

        return result.report_path
