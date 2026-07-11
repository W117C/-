"""SimpleCrawlerAdapter — built-in lightweight HTTP crawler (spec §3.2 ⑥ crawl_target).

This adapter does NOT wrap an external binary. It uses only Python stdlib
(`urllib.request` / `re`) to fetch a single page and extract reconnaissance
leads: forms, JS API endpoints, emails, and secret-leak hints in HTML comments.

Design notes:
- MVP is depth=1 (single page), mode="static" only. Multi-page crawling and
  browser rendering are deferred to a future pyspider adapter swap.
- `fetcher` is injectable for testability; production uses `_default_fetch`
  which goes through `urllib.request.urlopen`.
- Failures from the fetcher are re-raised as `ToolFailedError` so the gate
  and tool function can handle them uniformly.
"""
from __future__ import annotations

import datetime as dt
import re
import urllib.error
import urllib.request
import uuid
from typing import Any

from secagent.adapters.base import BaseAdapter
from secagent.core.errors import InvalidInputError, ToolFailedError
from secagent.core.finding import Finding, FindingType, Severity
from secagent.core.headers import random_ua

# Hint patterns that, when found inside an HTML comment, indicate a leaked secret.
_SECRET_HINT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),          # AWS access key id
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"private_key", re.I),
    re.compile(r"token\s*=", re.I),
]

_VALID_EXTRACT_TYPES = {"forms", "js_endpoints", "emails", "comments"}


def _default_fetch(url: str, timeout: int, proxy_manager=None) -> str:
    """Fetch `url` and return decoded text using urllib stdlib.

    Any network-level failure is wrapped in ToolFailedError so callers get a
    uniform error type regardless of the underlying stdlib exception.

    If *proxy_manager* is provided and proxy is enabled, uses a ProxyHandler
    to route requests through the configured proxy.
    """
    try:
        req = urllib.request.Request(url, headers={"User-Agent": random_ua("chrome_mac")})
        if proxy_manager and proxy_manager.is_enabled():
            handler = proxy_manager.build_proxy_handler()
            if handler:
                opener = urllib.request.build_opener(handler)
                with opener.open(req, timeout=timeout) as resp:
                    return resp.read().decode("utf-8", errors="replace")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.URLError as e:
        raise ToolFailedError(tool="simple_crawler", detail=f"fetch failed: {e}")
    except ToolFailedError:
        raise
    except Exception as e:
        raise ToolFailedError(tool="simple_crawler", detail=f"fetch error: {e}")


class SimpleCrawlerAdapter(BaseAdapter):
    """Built-in single-page HTTP crawler."""

    def __init__(self, timeout_sec: int = 30, fetcher=None, proxy_manager=None):
        self._timeout = timeout_sec
        self._fetcher = fetcher or (lambda url, t: _default_fetch(url, t, proxy_manager))

    @property
    def tool_name(self) -> str:
        return "simple_crawler"

    def run(self, params: dict[str, Any]) -> list[Finding]:
        url = params.get("target")
        if not url or not isinstance(url, str):
            raise InvalidInputError(field="target", reason="must be a non-empty URL")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise InvalidInputError(field="target", reason="must be http/https URL")

        extract = params.get("extract", ["forms", "js_endpoints", "emails", "comments"])
        # Normalize and validate the extract filter.
        if isinstance(extract, str):
            extract = [extract]
        extract_set = set(extract)
        unknown = extract_set - _VALID_EXTRACT_TYPES
        if unknown:
            raise InvalidInputError(
                field="extract",
                reason=f"unknown extract types: {sorted(unknown)}",
            )

        try:
            html = self._fetcher(url, self._timeout)
        except ToolFailedError:
            raise
        except Exception as e:
            # Wrap any fetcher-level exception (network or otherwise) so
            # callers see a uniform ToolFailedError regardless of fetcher.
            raise ToolFailedError(tool=self.tool_name, detail=f"fetch error: {e}")
        return self._parse(html, url, extract_set)

    def _parse(self, html: str, url: str, extract_types: set[str]) -> list[Finding]:
        findings: list[Finding] = []
        now = dt.datetime.now(dt.timezone.utc)

        if "forms" in extract_types:
            findings.extend(self._extract_forms(html, url, now))

        if "js_endpoints" in extract_types:
            findings.extend(self._extract_js_endpoints(html, url, now))

        if "emails" in extract_types:
            findings.extend(self._extract_emails(html, url, now))

        if "comments" in extract_types:
            findings.extend(self._extract_comments(html, url, now))

        return findings

    # ---- extractors -----------------------------------------------------------

    def _extract_forms(self, html: str, url: str, now: dt.datetime) -> list[Finding]:
        findings: list[Finding] = []
        # Match each <form ...> tag (opening tag only) and pull action + method.
        for m in re.finditer(r"<form\b[^>]*>", html, re.I):
            tag = m.group(0)
            action_m = re.search(r'\baction\s*=\s*(["\'])([^"\']*)\1', tag, re.I)
            method_m = re.search(r'\bmethod\s*=\s*(["\'])([^"\']*)\1', tag, re.I)
            action = action_m.group(2) if action_m else ""
            method = (method_m.group(2) if method_m else "get").lower() or "get"
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.EXPOSURE,
                severity=Severity.INFO,
                target=url,
                title=f"Form: action={action or '(none)'} method={method}",
                evidence={
                    "url": url,
                    "form_action": action,
                    "form_method": method,
                },
                source_tool=self.tool_name,
                timestamp=now,
            ))
        return findings

    def _extract_js_endpoints(self, html: str, url: str, now: dt.datetime) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        # Capture URL paths like "/api/..." or "/v1/..." wrapped in quotes.
        for m in re.finditer(r'["\'](/(?:api|v\d+)/[^\s"\']+)["\']', html, re.I):
            endpoint = m.group(1)
            if endpoint in seen:
                continue
            seen.add(endpoint)
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.EXPOSURE,
                severity=Severity.INFO,
                target=url,
                title=f"JS endpoint: {endpoint}",
                evidence={
                    "url": url,
                    "js_api": endpoint,
                },
                source_tool=self.tool_name,
                timestamp=now,
            ))
        return findings

    def _extract_emails(self, html: str, url: str, now: dt.datetime) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[str] = set()
        for m in re.finditer(r"[\w.+-]+@[\w-]+\.[\w.-]+", html):
            email = m.group(0)
            if email in seen:
                continue
            seen.add(email)
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.EXPOSURE,
                severity=Severity.INFO,
                target=url,
                title=f"Email: {email}",
                evidence={
                    "url": url,
                    "email": email,
                },
                source_tool=self.tool_name,
                timestamp=now,
            ))
        return findings

    def _extract_comments(self, html: str, url: str, now: dt.datetime) -> list[Finding]:
        findings: list[Finding] = []
        for m in re.finditer(r"<!--(.*?)-->", html, re.S):
            comment = m.group(1)
            hint = self._detect_secret_hint(comment)
            if not hint:
                continue
            findings.append(Finding(
                id=f"fnd_{uuid.uuid4().hex}",
                type=FindingType.EXPOSURE,
                severity=Severity.HIGH,
                target=url,
                title=f"Possible secret leak in HTML comment ({hint})",
                evidence={
                    "url": url,
                    "leaked_secret_hint": hint,
                    "comment_snippet": comment.strip()[:200],
                },
                source_tool=self.tool_name,
                timestamp=now,
            ))
        return findings

    @staticmethod
    def _detect_secret_hint(comment: str) -> str | None:
        for pat in _SECRET_HINT_PATTERNS:
            if pat.search(comment):
                return pat.pattern
        return None
