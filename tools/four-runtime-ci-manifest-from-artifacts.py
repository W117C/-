from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


RUNTIMES = ("python", "go", "rust", "java")
MANIFEST_SCHEMA = "spider.ci.artifact-manifest"
RUNTIME_CI_ARTIFACT_SCHEMA = "contracts/runtime-ci-artifact.schema.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_posix(path: str | Path) -> str:
    return str(path).replace("\\", "/")


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "missing"
    except json.JSONDecodeError as exc:
        return None, f"json-decode-error:{exc.msg}"
    except OSError as exc:
        return None, f"json-read-error:{exc}"
    if not isinstance(payload, dict):
        return None, "json-root-not-object"
    return payload, ""


def _portable_path(path: Path, repo_root: Path) -> str:
    resolved = path.resolve()
    root = repo_root.resolve()
    try:
        return _as_posix(resolved.relative_to(root))
    except ValueError:
        return _as_posix(resolved)


def _artifact_candidates(artifact_root: Path, runtime: str) -> list[Path]:
    if not artifact_root.exists():
        return []
    return sorted(
        artifact_root.rglob(f"{runtime}-runtime-ci.json"),
        key=lambda path: (len(path.parts), _as_posix(path).lower()),
    )


def _first_artifact(artifact_root: Path, runtime: str) -> Path | None:
    candidates = _artifact_candidates(artifact_root, runtime)
    return candidates[0] if candidates else None


def _coerce_status(value: Any) -> str:
    status = str(value or "blocked")
    return status if status in {"passed", "failed", "blocked", "partial"} else "blocked"


def _coerce_int(value: Any, default: int | None = 0) -> int | None:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    return default


def _artifact_item(runtime: str, path: Path, repo_root: Path) -> dict[str, Any]:
    payload, error = _read_json(path)
    artifact_path = _portable_path(path, repo_root)
    if payload is None:
        return {
            "runtime": runtime,
            "status": "blocked",
            "command": "",
            "duration-ms": 0,
            "exit-code": None,
            "artifact-paths": [artifact_path],
            "artifact-schema": RUNTIME_CI_ARTIFACT_SCHEMA,
            "source-state": "invalid",
            "source-error": error,
        }

    detected_runtime = str(payload.get("runtime", runtime))
    source_errors: list[str] = []
    if detected_runtime != runtime:
        source_errors.append(f"runtime-mismatch:{detected_runtime}")
    if payload.get("schema") != "spider.runtime-ci.artifact":
        source_errors.append("schema-mismatch")

    return {
        "runtime": runtime,
        "status": _coerce_status(payload.get("status")),
        "command": str(payload.get("command", "")),
        "duration-ms": _coerce_int(payload.get("duration-ms"), 0) or 0,
        "exit-code": _coerce_int(payload.get("exit-code"), None),
        "artifact-paths": [artifact_path],
        "artifact-schema": RUNTIME_CI_ARTIFACT_SCHEMA,
        "version": str(payload.get("version", "")),
        "source-state": "present" if not source_errors else "invalid",
        "source-error": ",".join(source_errors),
    }


def _derive_run_url() -> str:
    explicit = os.environ.get("GITHUB_RUN_URL", "").strip()
    if explicit:
        return explicit
    server = os.environ.get("GITHUB_SERVER_URL", "").strip()
    repository = os.environ.get("GITHUB_REPOSITORY", "").strip()
    run_id = os.environ.get("GITHUB_RUN_ID", "").strip()
    if server and repository and run_id:
        return f"{server.rstrip('/')}/{repository}/actions/runs/{run_id}"
    return ""


def buildManifest(
    artifactRoot: str | Path,
    repoRoot: str | Path = ".",
    ciProvider: str = "",
    runId: str = "",
    runUrl: str = "",
) -> dict[str, Any]:
    artifact_root = Path(artifactRoot)
    repo_root = Path(repoRoot)
    artifacts: list[dict[str, Any]] = []
    missing: list[str] = []

    for runtime in RUNTIMES:
        path = _first_artifact(artifact_root, runtime)
        if path is None:
            missing.append(runtime)
            continue
        artifacts.append(_artifact_item(runtime, path, repo_root))

    provider = ciProvider or ("github-actions" if os.environ.get("GITHUB_ACTIONS") == "true" else "local-artifact-directory")
    resolved_run_id = runId or os.environ.get("GITHUB_RUN_ID", "")
    resolved_run_url = runUrl or _derive_run_url()

    return {
        "schema": MANIFEST_SCHEMA,
        "generated-at": _now(),
        "ci-provider": provider,
        "run-id": str(resolved_run_id),
        "run-url": str(resolved_run_url),
        "artifact-root": _portable_path(artifact_root, repo_root) if artifact_root.exists() else _as_posix(artifact_root),
        "artifacts": artifacts,
        "summary": {
            "runtime-count": len(RUNTIMES),
            "artifact-count": len(artifacts),
            "missing-count": len(missing),
            "missing-runtimes": missing,
            "uses-artifacts-array": True,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-root", required=True)
    parser.add_argument("--repo-root", default=".")
    parser.add_argument("--output", required=True)
    parser.add_argument("--ci-provider", default="")
    parser.add_argument("--run-id", default="")
    parser.add_argument("--run-url", default="")
    args = parser.parse_args(argv)

    payload = buildManifest(
        artifactRoot=args.artifact_root,
        repoRoot=args.repo_root,
        ciProvider=args.ci_provider,
        runId=args.run_id,
        runUrl=args.run_url,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
