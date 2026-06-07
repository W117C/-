from __future__ import annotations

import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_ROLES = ["release-owner", "security-owner", "compliance-owner"]
READY_STATUSES = {"passed", "ready", "verified", "approved"}
ROOT = Path(__file__).resolve().parents[1]


def nowUtc() -> datetime:
    return datetime.now(timezone.utc)


def isoNow() -> str:
    return nowUtc().isoformat().replace("+00:00", "Z")


def parseTime(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def readJson(path: str | Path) -> dict[str, Any] | None:
    p = Path(path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


def writeJson(path: str | Path, payload: dict[str, Any]) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _base_path(path: str | Path | None) -> Path:
    if not path:
        return Path.cwd()
    candidate = Path(path)
    return candidate.parent if candidate.parent != Path("") else Path.cwd()


def _is_remote_ref(path: str) -> bool:
    return path.lower().startswith(("http://", "https://", "s3://", "gs://", "az://"))


def _artifact_errors(paths: list[Any], owner: str, approvalPath: str | Path | None) -> list[str]:
    errors: list[str] = []
    artifact_paths = [str(path) for path in paths if str(path).strip()]
    if not artifact_paths:
        return [f"{owner}-artifact-paths-required"]
    base = _base_path(approvalPath)
    for path in artifact_paths:
        if _is_remote_ref(path):
            errors.append(f"{owner}-artifact-not-locally-verifiable")
            continue
        resolved = Path(path) if Path(path).is_absolute() else base / path
        try:
            artifact = json.loads(resolved.read_text(encoding="utf-8"))
        except FileNotFoundError:
            errors.append(f"{owner}-artifact-missing")
            continue
        except json.JSONDecodeError:
            errors.append(f"{owner}-artifact-json-invalid")
            continue
        except OSError:
            errors.append(f"{owner}-artifact-unreadable")
            continue
        if not isinstance(artifact, dict):
            errors.append(f"{owner}-artifact-json-not-object")
            continue
        if artifact.get("dry-run") is True:
            errors.append(f"{owner}-artifact-dry-run")
        if artifact.get("placeholder") is True:
            errors.append(f"{owner}-artifact-placeholder")
        if artifact.get("production-ready") is not True:
            errors.append(f"{owner}-artifact-production-ready-not-true")
        if str(artifact.get("status", "")).strip() not in READY_STATUSES:
            errors.append(f"{owner}-artifact-status-not-ready")
    return errors


def _loadHumanConfirmationTool() -> Any:
    spec = importlib.util.spec_from_file_location("human_confirmation", ROOT / "tools" / "human-confirmation.py")
    if spec is None or spec.loader is None:
        return None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _human_confirmation_errors(confirmation: Any, current: datetime) -> list[str]:
    errors: list[str] = []
    if not isinstance(confirmation, dict) or not confirmation:
        return ["human-confirmation-approval-required"]
    if confirmation.get("state") != "approved":
        errors.append("human-confirmation-not-approved")
    binding = confirmation.get("approval-binding") if isinstance(confirmation.get("approval-binding"), dict) else {}
    if binding.get("approved-by-human") is not True:
        errors.append("human-confirmation-approved-by-human-not-true")
    for field in ("confirmation-id", "approval-id", "authorized-by", "signature-algorithm", "approval-signature"):
        if not str(confirmation.get(field, "")).strip():
            errors.append(f"human-confirmation-{field}-missing")
    expires_at = str(confirmation.get("expires-at", "")).strip()
    if expires_at:
        try:
            if parseTime(expires_at) <= current:
                errors.append("human-confirmation-expired")
        except ValueError:
            errors.append("human-confirmation-expiry-invalid")
    tool = _loadHumanConfirmationTool()
    if tool is None:
        errors.append("human-confirmation-tool-missing")
    elif confirmation.get("approval-signature"):
        expected = tool.signApproval(confirmation)
        if str(confirmation.get("approval-signature")) != expected:
            errors.append("human-confirmation-signature-invalid")
    return errors


def _policy_errors(policy: Any, approvalPath: str | Path | None) -> list[str]:
    errors: list[str] = []
    if not isinstance(policy, dict) or not policy:
        return ["policy-evidence-required"]
    for field in ("policy-enforced", "external-kms-verified", "durable-policy-log", "operator-approval-enforced"):
        if policy.get(field) is not True:
            errors.append(f"{field}-not-true")
    if policy.get("dry-run") is True:
        errors.append("policy-evidence-must-not-be-dry-run")
    if policy.get("placeholder") is True:
        errors.append("policy-evidence-must-not-be-placeholder")
    if policy.get("production-ready") is not True:
        errors.append("policy-evidence-production-ready-not-true")
    paths = policy.get("artifact-paths") if isinstance(policy.get("artifact-paths"), list) else []
    errors.extend(_artifact_errors(paths, "policy-evidence", approvalPath))
    return errors


def buildStatus(approval: dict[str, Any] | None, now: datetime | None = None, approvalPath: str | Path | None = None) -> dict[str, Any]:
    current = now or nowUtc()
    approval = approval or {}
    signatures = approval.get("signatures") if isinstance(approval.get("signatures"), list) else []
    signed_roles = sorted(
        {
            str(item.get("role", "")).strip()
            for item in signatures
            if str(item.get("role", "")).strip() in REQUIRED_ROLES
            and str(item.get("signer", "")).strip()
            and str(item.get("signature-id", "")).strip()
        }
    )
    missing_roles = sorted(set(REQUIRED_ROLES) - set(signed_roles))
    errors: list[str] = []
    if not approval:
        errors.append("missing-signed-operator-approval")
    if approval and approval.get("schema") != "spider.operator-approval.evidence":
        errors.append("approval-schema-invalid")
    if approval and approval.get("production-ready") is not True:
        errors.append("approval-production-ready-not-true")
    if approval and approval.get("signed-release-approved") is not True:
        errors.append("signed-release-approved-not-true")
    expires_at = str(approval.get("expires-at", "")).strip()
    if approval and not expires_at:
        errors.append("approval-expiry-required")
    elif expires_at:
        try:
            if parseTime(expires_at) <= current:
                errors.append("approval-expired")
        except ValueError:
            errors.append("approval-expiry-invalid")
    if approval.get("safety", {}).get("dry-run") is True:
        errors.append("approval-must-not-be-dry-run")
    if approval and missing_roles:
        errors.append("missing-required-approval-signatures")
    if approval:
        signer_by_role: dict[str, str] = {}
        role_counts = {role: 0 for role in REQUIRED_ROLES}
        for item in signatures:
            role = str(item.get("role", "")).strip()
            if role not in REQUIRED_ROLES:
                continue
            role_counts[role] += 1
            signer_by_role[role] = str(item.get("signer", "")).strip()
        if any(count > 1 for count in role_counts.values()):
            errors.append("duplicate-required-role-signature")
        signer_values = [signer for signer in signer_by_role.values() if signer]
        if len(set(signer_values)) != len(signer_values):
            errors.append("approval-signers-must-be-distinct")
        errors.extend(_policy_errors(approval.get("policy-evidence"), approvalPath))
        errors.extend(_human_confirmation_errors(approval.get("human-confirmation"), current))
    errors = list(dict.fromkeys(errors))
    approved = not errors
    return {
        "schema": "spider.production-operator-approval-status",
        "generated-at": isoNow(),
        "approval-state": "approved" if approved else "blocked",
        "production-ready": approved,
        "approval-schema": str(approval.get("schema", "")),
        "signed-release-approved": approval.get("signed-release-approved") is True,
        "dry-run": approval.get("safety", {}).get("dry-run") is True,
        "expires-at": expires_at,
        "required-roles": REQUIRED_ROLES,
        "signed-roles": signed_roles,
        "missing-roles": missing_roles,
        "errors": errors,
        "summary": {
            "error-count": len(errors),
            "required-role-count": len(REQUIRED_ROLES),
            "signed-role-count": len(signed_roles),
            "missing-role-count": len(missing_roles),
        },
        "safety": {
            "does-not-read-secrets": True,
            "does-not-run-network-probes": True,
            "does-not-self-approve-release": True,
        },
        "next-operator-actions": ["continue-go-live-signoff"] if approved else ["collect-release-security-compliance-signatures", "attach-policy-and-human-confirmation-evidence"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--approval", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--fail-on-blocked", action="store_true")
    args = parser.parse_args(argv)
    payload = buildStatus(readJson(args.approval), approvalPath=args.approval)
    writeJson(args.output, payload)
    return 2 if args.fail_on_blocked and payload["approval-state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
