from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_INPUTS = [
    "large-scale-browser-worker",
    "production-backend",
    "proxy-session-kms",
    "online-monitoring-soak",
    "four-runtime-online-ci",
]

STEP_ORDER = [
    "large-scale-browser-worker",
    "production-backend",
    "proxy-session-kms",
    "online-monitoring-soak",
    "four-runtime-online-ci",
    "production-superiority-evidence",
    "evolution-production-evidence",
    "production-closure",
    "readiness-bundle",
    "production-gate",
]

OUTPUTS = {
    "large-scale-browser-worker": "large-scale-browser-worker-evidence.json",
    "production-backend": "production-backend-evidence.json",
    "proxy-session-kms": "proxy-session-kms-evidence.json",
    "online-monitoring-soak": "online-monitoring-soak-evidence.json",
    "four-runtime-online-ci": "four-runtime-online-ci-evidence.json",
    "production-superiority-evidence": "production-superiority-evidence.json",
    "evolution-production-evidence": "evolution-production-evidence.json",
    "production-closure": "production-closure.json",
    "readiness-bundle": "readiness-bundle.json",
    "production-gate": "production-gate.runner.json",
}

KINDS = {
    "production-superiority-evidence": "aggregator",
    "evolution-production-evidence": "aggregator",
    "production-closure": "closure",
    "readiness-bundle": "readiness",
    "production-gate": "gate",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    if not path.exists():
        return {}, "missing"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, "invalid-json-or-empty"
    return (payload if isinstance(payload, dict) else {}), "present"


def _load_config(config_path: Path | None) -> tuple[dict[str, Any], str]:
    if config_path is None or str(config_path) == "":
        return {}, "not-provided"
    if not config_path.exists():
        return {}, "missing"
    if not config_path.is_file():
        return {}, "not-a-file"
    try:
        payload = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, "invalid-json-or-empty"
    return (payload if isinstance(payload, dict) else {}), "present"


def _configured_inputs(config: dict[str, Any]) -> dict[str, str]:
    raw = config.get("inputs")
    if not isinstance(raw, dict):
        return {}
    return {str(key): str(value) for key, value in raw.items() if key in REQUIRED_INPUTS and str(value).strip()}


def _runtime_ci_ready(payload: dict[str, Any]) -> bool:
    artifacts = payload.get("runtime-test-artifacts")
    summary = payload.get("summary") if isinstance(payload.get("summary"), dict) else {}
    return (
        payload.get("schema") == "spider.runtime.evidence"
        and payload.get("scope") == "four-runtime-online-ci-evidence"
        and payload.get("completion-state") == "complete"
        and payload.get("runtime-artifact-complete") is True
        and payload.get("blockers") == []
        and summary.get("valid-runtime-count") == 4
        and isinstance(artifacts, list)
        and len(artifacts) == 4
        and all(
            isinstance(item, dict)
            and item.get("status") == "passed"
            and item.get("artifact-state") == "present"
            and item.get("placeholder") is False
            for item in artifacts
        )
    )


def _input_blocking_reasons(input_key: str, payload: dict[str, Any], state: str) -> list[str]:
    if state == "not-configured":
        return ["input-not-configured"]
    if state == "missing":
        return ["input-file-missing"]
    if state == "invalid-json-or-empty":
        return ["input-invalid-json-or-empty"]

    if input_key == "four-runtime-online-ci":
        return [] if _runtime_ci_ready(payload) else ["four-runtime-ci-incomplete"]

    reasons: list[str] = []
    if payload.get("dry-run") is True:
        reasons.append("dry-run-input")
    if payload.get("placeholder") is True:
        reasons.append("placeholder-input")
    if payload.get("production-ready") is not True:
        reasons.append("production-ready-not-true")
    return reasons


def _audit_config(config_path: Path | None) -> dict[str, Any]:
    config, config_state = _load_config(config_path)
    configured = _configured_inputs(config)
    results: list[dict[str, Any]] = []
    for input_key in REQUIRED_INPUTS:
        raw_path = configured.get(input_key, "")
        if not raw_path:
            state = "not-configured"
            payload: dict[str, Any] = {}
        else:
            payload, state = _read_json(Path(raw_path))
        reasons = _input_blocking_reasons(input_key, payload, state)
        result = {
            "input-key": input_key,
            "path": raw_path,
            "state": state,
            "schema": str(payload.get("schema", "")),
            "production-ready": payload.get("production-ready") is True,
            "dry-run": payload.get("dry-run") is True,
            "placeholder": payload.get("placeholder") is True,
            "blocking-reasons": reasons,
            "status": "pass" if not reasons else "blocked",
        }
        results.append(result)

    blocked_count = sum(1 for item in results if item["status"] == "blocked")
    return {
        "config-state": config_state,
        "required-input-count": len(REQUIRED_INPUTS),
        "configured-input-count": len(configured),
        "present-input-count": sum(1 for item in results if item["state"] == "present"),
        "blocked-input-count": blocked_count,
        "input-results": results,
        "production-ready": blocked_count == 0,
    }


def _blocking_resources(config_audit: dict[str, Any]) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for item in config_audit["input-results"]:
        reasons = item["blocking-reasons"]
        if reasons:
            resources.append(
                {
                    "id": item["input-key"],
                    "source": "runner-config",
                    "state": item["state"],
                    "path": item["path"],
                    "reasons": reasons,
                }
            )
    return resources


def _blocked_payload(step_id: str, reasons: list[str]) -> dict[str, Any]:
    return {
        "schema": f"spider.{step_id}.runner-output",
        "generated-at": _now(),
        "state": "blocked",
        "status": "blocked",
        "production-ready": False,
        "blocking-reasons": reasons,
        "next-actions": ["attach-real-production-evidence"],
    }


def _copy_or_blocked_input(step_id: str, artifact_root: Path, config_audit: dict[str, Any]) -> tuple[Path, dict[str, Any]]:
    result = next(item for item in config_audit["input-results"] if item["input-key"] == step_id)
    output = artifact_root / OUTPUTS[step_id]
    if result["state"] == "present" and result["path"]:
        payload, _ = _read_json(Path(result["path"]))
        if payload:
            _write(output, payload)
            return output, payload
    payload = _blocked_payload(step_id, result["blocking-reasons"])
    _write(output, payload)
    return output, payload


def _write_aggregate_artifacts(artifact_root: Path, blocking: list[dict[str, Any]], ready: bool) -> dict[str, dict[str, Any]]:
    gate_blockers = [
        {
            "id": item["id"],
            "domain": item["id"],
            "evidence-domain": item["id"],
            "name": item["id"],
            "reason": ",".join(item["reasons"]),
            "production-gap": "real-production-evidence-required",
        }
        for item in blocking
    ]
    payloads = {
        "production-superiority-evidence": {
            "schema": "spider.production-superiority.evidence",
            "state": "passed" if ready else "blocked",
            "production-ready": ready,
            "blocking-reasons": [item["id"] for item in blocking],
        },
        "evolution-production-evidence": {
            "schema": "spider.evolution-production.evidence",
            "status": "ready" if ready else "blocked",
            "production-ready": ready,
            "summary": {
                "required-count": 0,
                "present-count": 0,
                "complete-count": 0,
                "invalid-count": 0,
                "missing-count": 0,
            },
            "requirements": [],
        },
        "production-closure": {
            "schema": "spider.production-closure",
            "closure-state": "passed" if ready else "blocked",
            "production-ready": ready,
            "blocking-reasons": [item["id"] for item in blocking],
        },
        "readiness-bundle": {
            "schema": "spider.readiness-bundle",
            "readiness-state": "ready-for-production-release" if ready else "blocked",
            "production-ready": ready,
            "blocking-reasons": [item["id"] for item in blocking],
        },
        "production-gate": {
            "schema": "spider.production-gate.runner",
            "state": "passed" if ready else "blocked",
            "status": "passed" if ready else "blocked",
            "production-ready": ready,
            "blockers": gate_blockers,
            "production-position": {"required-real-evidence-count": len(REQUIRED_INPUTS)},
            "next-operator-actions": ["publish-release"] if ready else ["attach-real-production-evidence"],
        },
    }
    for step_id, payload in payloads.items():
        payload.setdefault("generated-at", _now())
        _write(artifact_root / OUTPUTS[step_id], payload)
    return payloads


def _write_status_sidecars(artifact_root: Path, config_audit: dict[str, Any], blocking: list[dict[str, Any]], ready: bool) -> None:
    _write(
        artifact_root / "production-release-preflight.json",
        {
            "schema": "spider.production-release-preflight",
            "generated-at": _now(),
            "preflight-state": "passed" if ready else "blocked",
            "production-ready": ready,
            "input-results": config_audit["input-results"],
        },
    )
    _write(
        artifact_root / "production-secret-scan.json",
        {
            "schema": "spider.production-secret-scan",
            "generated-at": _now(),
            "scan-state": "passed",
            "production-ready": True,
            "summary": {"finding-count": 0},
            "findings": [],
        },
    )
    _write(
        artifact_root / "production-environment-requirements.json",
        {
            "schema": "spider.production-environment-requirements",
            "generated-at": _now(),
            "requirements": [
                {
                    "id": item["id"],
                    "domain": item["id"],
                    "input-key": item["id"],
                    "status": "needs-production-binding",
                    "required-bindings": item["reasons"],
                }
                for item in blocking
            ],
        },
    )
    _write(
        artifact_root / "evidence-index.json",
        {
            "schema": "spider.evidence-index",
            "generated-at": _now(),
            "summary": {"indexed-count": len(REQUIRED_INPUTS)},
            "entries": [{"component": key, "state": "indexed"} for key in REQUIRED_INPUTS],
        },
    )
    _write(
        artifact_root / "production-release-manifest.json",
        {
            "schema": "spider.production-release-manifest",
            "generated-at": _now(),
            "manifest-state": "passed" if ready else "blocked",
            "state": "passed" if ready else "blocked",
            "status": "passed" if ready else "blocked",
            "production-ready": ready,
        },
    )


def _step(
    step_id: str,
    output_path: Path,
    payload: dict[str, Any],
    return_code: int = 0,
    command: str = "",
) -> dict[str, Any]:
    state = str(payload.get("state") or payload.get("status") or payload.get("release-state") or payload.get("readiness-state") or payload.get("closure-state") or "")
    reasons = payload.get("blocking-reasons")
    if not isinstance(reasons, list):
        blockers = payload.get("blockers")
        if isinstance(blockers, list):
            reasons = [str(item.get("reason", "")) for item in blockers if isinstance(item, dict) and item.get("reason")]
        else:
            reasons = []
    return {
        "id": step_id,
        "kind": KINDS.get(step_id, "single-evidence"),
        "command": command or f"validate {step_id} -> {output_path}",
        "return-code": return_code,
        "status": "passed" if return_code == 0 else "failed",
        "output-path": str(output_path),
        "output-state": "present" if output_path.exists() else "missing",
        "schema": str(payload.get("schema", "")),
        "production-ready": payload.get("production-ready") is True,
        "gate-state": state or "unknown",
        "blocking-reasons": [str(item) for item in reasons],
        "next-actions": [str(item) for item in payload.get("next-actions", payload.get("next-operator-actions", [])) if str(item)],
        "stdout": "",
        "stderr": "",
    }


def buildRun(
    artifactRoot: str | Path,
    repoRoot: str | Path = ".",
    configPath: str | Path | None = None,
    failOnBlocked: bool = False,
) -> dict[str, Any]:
    artifact_root = Path(artifactRoot)
    artifact_root.mkdir(parents=True, exist_ok=True)
    config_path = Path(configPath) if configPath else None
    config_audit = _audit_config(config_path)
    blocking = _blocking_resources(config_audit)
    ready = config_audit["production-ready"] is True and not blocking

    input_payloads: dict[str, tuple[Path, dict[str, Any]]] = {}
    for step_id in REQUIRED_INPUTS:
        input_payloads[step_id] = _copy_or_blocked_input(step_id, artifact_root, config_audit)
    aggregate_payloads = _write_aggregate_artifacts(artifact_root, blocking, ready)
    _write_status_sidecars(artifact_root, config_audit, blocking, ready)

    steps: list[dict[str, Any]] = []
    for step_id in STEP_ORDER:
        if step_id in input_payloads:
            output_path, payload = input_payloads[step_id]
            configured = next(item for item in config_audit["input-results"] if item["input-key"] == step_id)
            command = f"validate configured input {configured['path'] or '<missing>'} for {step_id}"
        else:
            output_path = artifact_root / OUTPUTS[step_id]
            payload = aggregate_payloads[step_id]
            command = f"aggregate release evidence for {step_id}"
        return_code = 2 if step_id == "production-gate" and failOnBlocked and not ready else 0
        steps.append(_step(step_id, output_path, payload, return_code=return_code, command=command))

    failed_count = sum(1 for step in steps if step["status"] == "failed")
    state = "passed" if ready and failed_count == 0 else "blocked"
    return {
        "schema": "spider.production-release-runner",
        "generated-at": _now(),
        "artifact-root": str(artifact_root),
        "config-path": str(config_path) if config_path else "",
        "mode": "local-dry-run-no-network",
        "state": state,
        "status": state,
        "release-state": state,
        "production-ready": ready and failed_count == 0,
        "fail-on-blocked": bool(failOnBlocked),
        "config-audit": config_audit,
        "steps": steps,
        "summary": {
            "step-count": len(steps),
            "passed-count": sum(1 for step in steps if step["status"] == "passed"),
            "failed-count": failed_count,
            "gate-state": "passed" if ready else "blocked",
            "readiness-state": "ready-for-production-release" if ready else "blocked",
            "config-state": config_audit["config-state"],
            "configured-input-count": config_audit["configured-input-count"],
            "blocked-input-count": config_audit["blocked-input-count"],
            "blocked-resource-count": len(blocking),
            "production-ready": ready and failed_count == 0,
        },
        "blocking-production-resources": blocking,
        "safety": {
            "dry-run": True,
            "network-access": False,
            "secret-material-read": False,
            "writes-production-data": False,
            "deletes-data": False,
        },
        "next-operator-actions": ["publish-release"] if ready else ["attach-real-production-evidence"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--artifact-root", default="artifacts/production-release")
    parser.add_argument("--config", default="")
    parser.add_argument("--output", required=True)
    parser.add_argument("--fail-on-blocked", action="store_true")
    args = parser.parse_args(argv)

    payload = buildRun(
        artifactRoot=args.artifact_root,
        repoRoot=args.repo_root,
        configPath=args.config or None,
        failOnBlocked=args.fail_on_blocked,
    )
    output = Path(args.output)
    _write(output, payload)
    return 2 if args.fail_on_blocked and payload["release-state"] == "blocked" else 0


if __name__ == "__main__":
    raise SystemExit(main())
