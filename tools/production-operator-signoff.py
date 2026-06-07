from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_ROLES = ["release-owner", "security-owner", "compliance-owner"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _read(path: str | Path) -> dict[str, Any]:
    p = Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _write(path: str | Path, payload: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _approval_status(approval: dict[str, Any], approval_path: str | Path = "") -> dict[str, Any]:
    spec = importlib.util.spec_from_file_location(
        "production_operator_approval_status",
        ROOT / "tools" / "production-operator-approval-status.py",
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot-load-production-operator-approval-status")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.buildStatus(approval, approvalPath=approval_path)


def _add_blocker(blockers: list[dict[str, str]], blocker_id: str, reason: str) -> None:
    entry = {"id": blocker_id, "state": "blocked", "reason": reason}
    if entry not in blockers:
        blockers.append(entry)


def _blocked_actions(blockers: list[dict[str, str]]) -> list[str]:
    if not blockers:
        return ["publish-release"]
    actions: list[str] = []
    blocker_ids = {blocker["id"] for blocker in blockers}
    if "production-access-status" in blocker_ids:
        actions.append("repair-production-access-status")
    if "production-release-runner" in blocker_ids:
        actions.append("rerun-production-release-evidence")
    if "operator-approval-evidence" in blocker_ids:
        actions.append("collect-release-security-compliance-signatures")
    if "proxy-session-kms-evidence" in blocker_ids:
        actions.append("attach-real-proxy-session-kms-evidence")
    return actions or ["repair-production-signoff-blockers"]


def buildSignoff(
    accessStatusPath: str | Path,
    releaseRunnerPath: str | Path,
    approvalPath: str | Path,
    proxySessionKmsPath: str | Path = "",
) -> dict[str, Any]:
    access = _read(accessStatusPath)
    runner = _read(releaseRunnerPath)
    approval = _read(approvalPath)
    proxy_session_kms = _read(proxySessionKmsPath) if proxySessionKmsPath else {}
    approval_status = _approval_status(approval, approvalPath)
    blockers: list[dict[str, str]] = []
    if access.get("access-state") != "ready-for-production-evidence-runner":
        _add_blocker(blockers, "production-access-status", "access-not-ready-for-production-evidence-runner")
    if runner.get("release-state") != "passed" or runner.get("production-ready") is not True:
        _add_blocker(blockers, "production-release-runner", "release-runner-not-production-ready")
    if approval_status["approval-state"] != "approved":
        approval_errors = approval_status.get("errors") if isinstance(approval_status.get("errors"), list) else []
        for reason in approval_errors or ["signed-operator-approval-required"]:
            _add_blocker(blockers, "operator-approval-evidence", str(reason))
    if not proxySessionKmsPath:
        _add_blocker(blockers, "proxy-session-kms-evidence", "proxy-session-kms-path-required")
    elif not Path(proxySessionKmsPath).exists():
        _add_blocker(blockers, "proxy-session-kms-evidence", "proxy-session-kms-evidence-file-missing")
    if proxySessionKmsPath and (
        proxy_session_kms.get("schema") != "spider.proxy-session-kms.evidence"
        or proxy_session_kms.get("status") != "ready"
        or proxy_session_kms.get("production-ready") is not True
    ):
        proxy_blockers = proxy_session_kms.get("blockers") if isinstance(proxy_session_kms.get("blockers"), list) else []
        for reason in proxy_blockers or ["proxy-session-kms-production-evidence-required"]:
            _add_blocker(blockers, "proxy-session-kms-evidence", str(reason))
    signed_roles = approval_status["signed-roles"]
    ready = not blockers
    return {
        "schema": "spider.production-operator-signoff",
        "generated-at": _now(),
        "signoff-state": "release-ready" if ready else "blocked",
        "production-ready": ready,
        "inputs": {
            "production-access-status": str(accessStatusPath),
            "production-release-runner": str(releaseRunnerPath),
            "operator-approval-evidence": str(approvalPath),
            "proxy-session-kms-evidence": str(proxySessionKmsPath),
        },
        "checks": {
            "access-state": str(access.get("access-state", "missing")),
            "access-ready-for-evidence-runner": access.get("access-state") == "ready-for-production-evidence-runner",
            "release-state": str(runner.get("release-state", "missing")),
            "release-runner-production-ready": runner.get("production-ready") is True,
            "approval-schema": str(approval.get("schema", "missing")),
            "signed-release-approved": approval_status["signed-release-approved"],
            "proxy-session-kms-schema": str(proxy_session_kms.get("schema", "missing")),
            "proxy-session-kms-status": str(proxy_session_kms.get("status", "missing")),
            "proxy-session-kms-production-ready": proxy_session_kms.get("production-ready") is True,
            "required-roles": REQUIRED_ROLES,
            "signed-roles": signed_roles,
        },
        "blockers": blockers,
        "summary": {
            "blocker-count": len(blockers),
            "required-role-count": len(REQUIRED_ROLES),
            "signed-role-count": len(signed_roles),
        },
        "safety": {
            "does-not-read-secrets": True,
            "does-not-run-network-probes": True,
            "does-not-self-approve-release": True,
            "requires-human-signatures": True,
        },
        "next-operator-actions": _blocked_actions(blockers),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--access-status", required=True)
    parser.add_argument("--release-runner", required=True)
    parser.add_argument("--approval", required=True)
    parser.add_argument("--proxy-session-kms", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--fail-on-blocked", action="store_true")
    args = parser.parse_args(argv)
    payload = buildSignoff(args.access_status, args.release_runner, args.approval, proxySessionKmsPath=args.proxy_session_kms)
    _write(args.output, payload)
    return 2 if args.fail_on_blocked and payload["signoff-state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
