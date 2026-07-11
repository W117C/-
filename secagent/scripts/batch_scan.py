"""Batch web vulnerability scan → client-ready report.

Reads a list of target URLs (one per line) from a file, runs the
`web_vuln_scan` tool against each (within the scope of a single issued
authorization token), aggregates the engagements, and renders a
client-deliverable Markdown report.

Usage:
    python scripts/batch_scan.py \
        --targets targets.txt \
        --token auth_xxx \
        --client "ACME Corp" \
        --engagement PO-2026-001 \
        --authorized "Authorized by ACME per PO-2026-001" \
        --output report.md

The token must be issued and verified first:
    secagent authz add --domain acme.com --note "pentest PO-2026-001"
    secagent authz verify <token>

All scans honor the compliance gate (scope + blocklist + quota), so a
target outside the authorized scope is refused rather than scanned.
"""

from __future__ import annotations

import argparse
import sys

from secagent.config import Config
from secagent.core.gate import ComplianceGate
from secagent.core.registry import AuthorizationRegistry
from secagent.report.client_report import render_client_report
from secagent.storage.sqlite_store import SQLiteStore
import secagent.tools.web_vuln_scan as _wv_module


def _read_targets(path: str) -> list[str]:
    """Read non-empty, non-comment lines from the targets file."""
    targets: list[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            targets.append(line)
    return targets


def _build_gate(scope_db_path: str, default_quota: int) -> ComplianceGate:
    store = SQLiteStore(scope_db_path)
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=default_quota)
    return ComplianceGate(store, reg.quota, default_quota=default_quota)


def run_batch(
    targets: list[str],
    token: str,
    *,
    client_name: str = "",
    engagement_ref: str = "",
    authorized_by: str = "",
    modules: list[str] | None = None,
) -> str:
    """Scan all targets and return a client-ready Markdown report.

    Raises the same compliance errors as a single scan if the token is
    missing/unverified or a target is out of scope — surfaced to the caller.
    """
    cfg = Config.load()
    gate = _build_gate(cfg.db_path, cfg.default_quota_per_token)

    engagements: list[dict] = []
    for target in targets:
        params: dict = {"target": target}
        if modules:
            params["modules"] = modules
        try:
            result = _wv_module.web_vuln_scan(
                gate=gate, params=params, authz_token=token, caller_id="batch_scan"
            )
        except Exception as exc:  # compliance refusal or tool failure
            # Record a failed engagement so the report notes the refusal.
            engagements.append({
                "tool": "web_vuln_scan",
                "engagement_id": f"refused_{target}",
                "quota_used": 0,
                "findings": [{
                    "id": f"fnd_refuse_{target}",
                    "type": "compliance_refusal",
                    "severity": "info",
                    "target": target,
                    "title": f"Scan refused: {type(exc).__name__}: {exc}",
                    "confidence": "validated",
                    "evidence": {},
                }],
            })
            continue

        if result.get("error"):
            engagements.append({
                "tool": "web_vuln_scan",
                "engagement_id": result.get("engagement_id", f"err_{target}"),
                "quota_used": result.get("quota_used", 0),
                "findings": [{
                    "id": f"fnd_err_{target}",
                    "type": "tool_error",
                    "severity": "info",
                    "target": target,
                    "title": f"Scan error: {result['error'].get('message', 'unknown')}",
                    "confidence": "validated",
                    "evidence": {},
                }],
            })
            continue

        engagements.append({
            "tool": result["tool"],
            "engagement_id": result.get("engagement_id", ""),
            "quota_used": result.get("quota_used", 0),
            "findings": result.get("findings", []),
        })

    return render_client_report(
        engagements,
        client_name=client_name,
        engagement_ref=engagement_ref,
        authorized_by=authorized_by,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch web vuln scan → client report")
    parser.add_argument("--targets", required=True, help="File with one target URL per line")
    parser.add_argument("--token", required=True, help="Issued + verified authz token")
    parser.add_argument("--client", default="", help="Client name for the report cover")
    parser.add_argument("--engagement", default="", help="Engagement / PO reference")
    parser.add_argument("--authorized", default="", help="Authorization scope note")
    parser.add_argument("--output", default=None, help="Write report to this path (default: stdout)")
    parser.add_argument(
        "--modules", default=None,
        help="Comma-separated modules to run (sqli,xss,ssrf,lfi). Default: all.",
    )
    args = parser.parse_args(argv)

    targets = _read_targets(args.targets)
    if not targets:
        sys.stderr.write(f"No targets found in {args.targets}\n")
        return 2

    modules = args.modules.split(",") if args.modules else None

    try:
        report = run_batch(
            targets,
            args.token,
            client_name=args.client,
            engagement_ref=args.engagement,
            authorized_by=args.authorized,
            modules=modules,
        )
    except Exception as exc:
        sys.stderr.write(f"Batch scan failed: {type(exc).__name__}: {exc}\n")
        return 1

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"Report written to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
