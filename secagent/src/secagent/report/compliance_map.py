"""Compliance framework mapping (spec §M9).

Maps internal vulnerability classes (``vuln_class`` strings emitted by the
detectors, e.g. ``sqli_error``, ``xss_reflected``, ``ssrf_oob``, ``lfi_traversal``)
to the clauses of common compliance frameworks that customers ask about:

  * OWASP Top 10 (2021)
  * PCI-DSS v4.0
  * SOC 2 (Common Criteria)

This is a *reference mapping* for client-facing reports — it tells a customer
which control families a finding implicates, helping them scope remediation to
their audit obligations. It is intentionally conservative: a finding maps only
to frameworks/clauses it clearly relates to, and the report states the mapping
is advisory (not a formal compliance attestation).
"""

from __future__ import annotations

from typing import Any

# Map a vuln_class (or its family prefix) to framework clauses.
# Keyed by the exact vuln_class first, then by family prefix (sqli_, xss_, ...).
_COMPLIANCE_MAP: dict[str, dict[str, str]] = {
    # --- SQL Injection ---
    "sqli_error": {
        "OWASP 2021": "A03:2021 – Injection",
        "PCI-DSS v4.0": "Req 6.5.1 – Injection flaws (SQL)",
        "SOC 2": "CC6.1 – Logical access / input validation",
    },
    "sqli_blind_time": {
        "OWASP 2021": "A03:2021 – Injection",
        "PCI-DSS v4.0": "Req 6.5.1 – Injection flaws (SQL)",
        "SOC 2": "CC6.1 – Logical access / input validation",
    },
    "sqli_blind_boolean": {
        "OWASP 2021": "A03:2021 – Injection",
        "PCI-DSS v4.0": "Req 6.5.1 – Injection flaws (SQL)",
        "SOC 2": "CC6.1 – Logical access / input validation",
    },
    # --- XSS ---
    "xss_reflected": {
        "OWASP 2021": "A03:2021 – Injection (XSS)",
        "PCI-DSS v4.0": "Req 6.5.7 – Cross-site scripting (XSS)",
        "SOC 2": "CC6.1 – Logical access / input validation",
    },
    "xss_stored": {
        "OWASP 2021": "A03:2021 – Injection (XSS)",
        "PCI-DSS v4.0": "Req 6.5.7 – Cross-site scripting (XSS)",
        "SOC 2": "CC6.1 – Logical access / input validation",
    },
    # --- SSRF ---
    "ssrf_internal": {
        "OWASP 2021": "A10:2021 – Server-Side Request Forgery",
        "PCI-DSS v4.0": "Req 6.5.5 – SSRF",
        "SOC 2": "CC6.1 / CC6.6 – Boundary / access controls",
    },
    "ssrf_oob": {
        "OWASP 2021": "A10:2021 – Server-Side Request Forgery",
        "PCI-DSS v4.0": "Req 6.5.5 – SSRF",
        "SOC 2": "CC6.1 / CC6.6 – Boundary / access controls",
    },
    # --- LFI / Path Traversal ---
    "lfi_traversal": {
        "OWASP 2021": "A01:2021 – Broken Access Control (path traversal)",
        "PCI-DSS v4.0": "Req 6.5.8 – Improper access control",
        "SOC 2": "CC6.1 / CC6.3 – Access enforcement",
    },
    # --- IDOR / Broken Access Control ---
    "idor_adjacent_access": {
        "OWASP 2021": "A01:2021 – Broken Access Control",
        "PCI-DSS v4.0": "Req 6.5.8 – Improper access control",
        "SOC 2": "CC6.1 / CC6.3 – Access enforcement",
    },
    # --- XXE ---
    "xxe_echo": {
        "OWASP 2021": "A05:2021 – Security Misconfiguration (XXE)",
        "PCI-DSS v4.0": "Req 6.5.8 – Improper access control (XXE)",
        "SOC 2": "CC6.1 / CC7.1 – Input handling",
    },
    "xxe_oob": {
        "OWASP 2021": "A05:2021 – Security Misconfiguration (XXE)",
        "PCI-DSS v4.0": "Req 6.5.8 – Improper access control (XXE)",
        "SOC 2": "CC6.1 / CC7.1 – Input handling",
    },
}

# Family-prefix fallback: "sqli_" matches any sqli_* class not listed above.
_FAMILY_FALLBACK: dict[str, dict[str, str]] = {
    "sqli_": _COMPLIANCE_MAP["sqli_error"],
    "xss_": _COMPLIANCE_MAP["xss_reflected"],
    "ssrf_": _COMPLIANCE_MAP["ssrf_internal"],
    "lfi_": _COMPLIANCE_MAP["lfi_traversal"],
    "idor_": _COMPLIANCE_MAP["idor_adjacent_access"],
    "xxe_": _COMPLIANCE_MAP["xxe_echo"],
}

FRAMEWORKS: list[str] = ["OWASP 2021", "PCI-DSS v4.0", "SOC 2"]


def map_finding(vuln_class: str | None, finding_type: str | None = None) -> dict[str, str]:
    """Return {framework: clause} for a single finding.

    Looks up by exact ``vuln_class`` first, then by family prefix, then by
    ``finding_type``. Returns an empty dict when nothing matches.
    """
    key = vuln_class or finding_type or ""
    if key in _COMPLIANCE_MAP:
        return dict(_COMPLIANCE_MAP[key])
    for prefix, clauses in _FAMILY_FALLBACK.items():
        if key.startswith(prefix):
            return dict(clauses)
    return {}


def map_engagements(engagements: Any) -> dict[str, set[str]]:
    """Aggregate compliance impact across all findings.

    Returns {framework: set(clause, ...)} so the report can list, per
    framework, every clause implicated by the scan.
    """
    from secagent.report._common import _normalize

    impact: dict[str, set[str]] = {fw: set() for fw in FRAMEWORKS}
    for eng in _normalize(engagements):
        for f in (eng.get("findings", []) or []):
            ev = f.get("evidence", {}) or {}
            clauses = map_finding(
                ev.get("vuln_class") or f.get("type"), f.get("type")
            )
            for fw, clause in clauses.items():
                impact.setdefault(fw, set()).add(clause)
    return impact
