from __future__ import annotations

# 中文注释：本工具只归一化在线 CI 已产出的四运行时制品清单，不启动 Python/Go/Rust/Java 测试命令。
# 中文注释：输出字段全部使用连字符键名，保证和 production evidence contract、schema 校验保持一致。

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


# 中文注释：四运行时顺序是 evidence contract 的稳定顺序，测试和下游 gate 都依赖该顺序。
RUNTIMES = ("python", "go", "rust", "java")
EVIDENCE_MODE = "real-ci-artifact-manifest-normalization-no-exec"
RUNTIME_CI_ARTIFACT_SCHEMA = "contracts/runtime-ci-artifact.schema.json"
RUN_URL_PLACEHOLDER_MARKERS = (
    "placeholder",
    "replace-me",
    "changeme",
    "todo",
    "{",
    "}",
)


# 中文注释：每个运行时必须由对应的真实 CI 命令产出，避免把占位脚本误标为在线 CI 通过。
COMMAND_PREFIXES = {
    "python": ("python -m pytest", "pytest"),
    "go": ("go test",),
    "rust": ("cargo test",),
    "java": ("mvn ", "mvn.cmd ", "mvnw ", "./mvnw ", ".\\mvnw "),
}


def _now() -> str:
    """中文注释：生成 UTC 时间戳，用于 evidence 审计和跨 CI 系统对齐。"""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _as_posix(path: str | Path) -> str:
    """中文注释：把 Windows 路径统一成 JSON 中更稳定的 POSIX 风格字符串。"""
    return str(path).replace("\\", "/")


def _resolve_artifact_path(path: str, repo_root: Path) -> Path:
    """中文注释：manifest 中的相对制品路径按 repo-root 解析，绝对路径保持原样。"""
    candidate = Path(path)
    if candidate.is_absolute():
        return candidate
    return repo_root / candidate


def _read_json(path: Path) -> tuple[dict[str, Any] | None, str]:
    """中文注释：读取本地 JSON；失败时返回错误字符串，调用方负责转成 blocker。"""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, "ci-artifact-manifest-missing"
    except json.JSONDecodeError as exc:
        return None, f"json-decode-error:{exc.msg}"
    except OSError as exc:
        return None, f"json-read-error:{exc}"
    if not isinstance(payload, dict):
        return None, "json-root-not-object"
    return payload, ""


def _run_url_errors(run_url: Any) -> list[str]:
    """中文注释：在线 CI evidence 必须指向真实 run URL，示例/占位/无效 URL 一律阻断。"""
    value = str(run_url or "").strip()
    if not value:
        return ["ci-run-url-missing"]

    errors: list[str] = []
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc or any(char.isspace() for char in value):
        errors.append("ci-run-url-invalid")

    lower = value.lower()
    if "example" in lower:
        errors.append("ci-run-url-example")
    if any(marker in lower for marker in RUN_URL_PLACEHOLDER_MARKERS):
        errors.append("ci-run-url-placeholder")
    return errors


def _command_matches(runtime: str, command: str) -> bool:
    """中文注释：按运行时校验 CI 命令前缀，防止 echo 等非测试命令伪造通过。"""
    normalized = " ".join(str(command).strip().split()).lower()
    if not normalized:
        return False
    prefixes = COMMAND_PREFIXES[runtime]
    if runtime == "java":
        return any(normalized.startswith(prefix) for prefix in prefixes) and " test" in f" {normalized}"
    return any(normalized.startswith(prefix) for prefix in prefixes)


def _artifact_path_states(paths: list[str], repo_root: Path) -> list[dict[str, Any]]:
    """中文注释：为每条 artifact-path 生成存在性明细，下游可定位缺失文件。"""
    states: list[dict[str, Any]] = []
    for path in paths:
        resolved = _resolve_artifact_path(path, repo_root)
        states.append(
            {
                "path": path,
                "exists": resolved.is_file(),
                "resolved-path": _as_posix(resolved),
            }
        )
    return states


def _artifact_schema_valid(runtime: str, path_states: list[dict[str, Any]]) -> tuple[bool, str]:
    """中文注释：轻量读取第一个存在的 runtime-ci artifact，确认 schema 和 runtime 没有串线。"""
    present_paths = [item for item in path_states if item["exists"]]
    if not present_paths:
        return False, "artifact-paths-all-missing"
    first_path = Path(present_paths[0]["resolved-path"])
    payload, error = _read_json(first_path)
    if payload is None:
        return False, f"artifact-json-invalid:{error}"
    if payload.get("schema") != "spider.runtime-ci.artifact":
        return False, "artifact-schema-mismatch"
    if payload.get("runtime") != runtime:
        return False, f"artifact-runtime-mismatch:{payload.get('runtime', '')}"
    return True, ""


def _validate_manifest_item(runtime: str, item: dict[str, Any] | None, repo_root: Path) -> dict[str, Any]:
    """中文注释：校验单个运行时 manifest 条目，并归一化为 files 数组的 schema-valid 记录。"""
    errors: list[str] = []
    if not isinstance(item, dict):
        errors.append("manifest-runtime-item-missing")
        item = {}

    status = str(item.get("status", "blocked"))
    if status not in {"passed", "failed", "blocked", "partial"}:
        errors.append("status-invalid")
        status = "blocked"

    command = str(item.get("command", ""))
    if not _command_matches(runtime, command):
        errors.append("command-does-not-match-runtime-ci-contract")

    duration_ms = item.get("duration-ms", 0)
    if not isinstance(duration_ms, int):
        errors.append("duration-ms-missing-or-nonpositive")
        duration_ms = 0
    elif duration_ms <= 0:
        errors.append("duration-ms-missing-or-nonpositive")

    exit_code = item.get("exit-code")
    if not isinstance(exit_code, int):
        errors.append("exit-code-missing")
        exit_code = None
    elif exit_code != 0:
        errors.append("exit-code-nonzero")

    artifact_paths_raw = item.get("artifact-paths", [])
    artifact_paths = [str(path) for path in artifact_paths_raw] if isinstance(artifact_paths_raw, list) else []
    if not artifact_paths:
        errors.append("artifact-paths-empty")
    path_states = _artifact_path_states(artifact_paths, repo_root)
    for state in path_states:
        if not state["exists"]:
            errors.append(f"artifact-paths-missing-on-disk:{state['path']}")
    if artifact_paths and all(state["exists"] for state in path_states):
        schema_valid, schema_error = _artifact_schema_valid(runtime, path_states)
        if not schema_valid:
            errors.append(schema_error)

    return {
        "runtime": runtime,
        "status": status,
        "valid": not errors and status == "passed",
        "errors": errors,
        "command": command,
        "duration-ms": duration_ms if isinstance(duration_ms, int) and duration_ms > 0 else 0,
        "exit-code": exit_code,
        "artifact-paths": artifact_paths,
        "artifact-path-states": path_states,
    }


def _blocked_file(runtime: str, error: str) -> dict[str, Any]:
    """中文注释：manifest 缺失或无效时，为每个运行时生成阻断态 files 记录。"""
    return {
        "runtime": runtime,
        "status": "blocked",
        "valid": False,
        "errors": [error],
        "command": "",
        "duration-ms": 0,
        "exit-code": None,
        "artifact-paths": [],
        "artifact-path-states": [],
    }


def _runtime_artifact_from_file(file_item: dict[str, Any]) -> dict[str, Any]:
    """中文注释：把 files 明细收敛成 production gate 直接读取的 runtime-test-artifacts 记录。"""
    present_paths = [state["path"] for state in file_item["artifact-path-states"] if state["exists"]]
    artifact_state = "present" if file_item["valid"] and present_paths else "missing"
    return {
        "runtime": file_item["runtime"],
        "status": file_item["status"] if file_item["valid"] else "blocked",
        "command": file_item["command"],
        "artifact-path": present_paths[0] if artifact_state == "present" else "",
        "artifact-paths": present_paths if artifact_state == "present" else [],
        "artifact-state": artifact_state,
        "artifact-schema": RUNTIME_CI_ARTIFACT_SCHEMA,
        "exit-code": file_item["exit-code"],
        "duration-ms": file_item["duration-ms"],
        "placeholder": artifact_state != "present",
    }


def _runtime_summary(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    """中文注释：生成按运行时索引的制品状态摘要，便于 readiness bundle 汇总。"""
    summary: dict[str, Any] = {}
    for item in artifacts:
        runtime = item["runtime"]
        present = 1 if item["artifact-state"] == "present" else 0
        summary[runtime] = {
            "artifact-count": len(item["artifact-paths"]),
            "present-count": present,
            "missing-count": 0 if present else 1,
            "passed-count": 1 if item["status"] == "passed" else 0,
            "failed-count": 1 if item["status"] == "failed" else 0,
            "blocked-count": 1 if item["status"] == "blocked" else 0,
            "partial-count": 1 if item["status"] == "partial" else 0,
            "status": item["status"],
        }
    return summary


def _completion_state(valid_count: int, blockers: list[str]) -> str:
    """中文注释：四个运行时全部有效才 complete；部分有效时保守标记 partial，否则 blocked。"""
    if not blockers and valid_count == len(RUNTIMES):
        return "complete"
    if valid_count > 0:
        return "partial"
    return "blocked"


def _manifest_metadata(
    path: Path,
    state: str,
    error: str,
    payload: dict[str, Any] | None,
    run_url_errors: list[str] | None = None,
) -> dict[str, Any]:
    """中文注释：归一化 manifest 元数据，缺失字段保持空字符串以满足 schema。"""
    payload = payload or {}
    artifacts = payload.get("artifacts", [])
    run_url_errors = run_url_errors or []
    return {
        "path": _as_posix(path),
        "state": state,
        "error": error,
        "ci-provider": str(payload.get("ci-provider", "")),
        "run-id": str(payload.get("run-id", "")),
        "run-url": str(payload.get("run-url", "")),
        "run-url-state": "valid" if not run_url_errors else "blocked",
        "run-url-errors": run_url_errors,
        "has-runtime-results": "runtime-results" in payload,
        "item-count": len(artifacts) if isinstance(artifacts, list) else 0,
    }


def buildEvidence(manifestPath: str | Path, repoRoot: str | Path) -> dict[str, Any]:
    """中文注释：构建四运行时在线 CI evidence；只校验证据文件，不执行测试命令。"""
    repo_root = Path(repoRoot)
    manifest_path = Path(manifestPath)
    manifest_payload, manifest_error = _read_json(manifest_path)
    blockers: list[str] = []

    if manifest_payload is None:
        state = "missing" if manifest_error == "ci-artifact-manifest-missing" else "invalid"
        blocker = "ci-artifact-manifest-missing" if state == "missing" else "ci-artifact-manifest-invalid"
        blockers.append(blocker)
        run_url_blockers: list[str] = []
        files = [_blocked_file(runtime, blocker) for runtime in RUNTIMES]
    else:
        state = "present"
        run_url_blockers = _run_url_errors(manifest_payload.get("run-url"))
        blockers.extend(run_url_blockers)
        if "runtime-results" in manifest_payload:
            blockers.append("ci-artifact-manifest-runtime-results-deprecated")
        artifacts = manifest_payload.get("artifacts")
        if not isinstance(artifacts, list):
            state = "invalid"
            if "runtime-results" in manifest_payload:
                manifest_error = "runtime-results-deprecated-use-artifacts"
                files = [_blocked_file(runtime, "ci-artifact-manifest-runtime-results-deprecated") for runtime in RUNTIMES]
            else:
                manifest_error = "artifacts-not-list"
                blockers.append("ci-artifact-manifest-invalid")
                files = [_blocked_file(runtime, "ci-artifact-manifest-invalid") for runtime in RUNTIMES]
        else:
            by_runtime: dict[str, dict[str, Any]] = {}
            for artifact in artifacts:
                if isinstance(artifact, dict) and artifact.get("runtime") in RUNTIMES:
                    by_runtime[str(artifact["runtime"])] = artifact
            files = [_validate_manifest_item(runtime, by_runtime.get(runtime), repo_root) for runtime in RUNTIMES]
            for file_item in files:
                blockers.extend(f"{file_item['runtime']}:{error}" for error in file_item["errors"])

    runtime_artifacts = [_runtime_artifact_from_file(item) for item in files]
    valid_count = sum(1 for item in files if item["valid"])
    runtime_artifact_complete = valid_count == len(RUNTIMES) and not blockers
    completion_state = _completion_state(valid_count, blockers)
    passed_count = sum(1 for item in runtime_artifacts if item["status"] == "passed" and not item["placeholder"])
    failed_count = sum(1 for item in runtime_artifacts if item["status"] == "failed")
    blocked_count = sum(1 for item in runtime_artifacts if item["status"] == "blocked")
    missing_count = sum(1 for item in runtime_artifacts if item["artifact-state"] == "missing")

    return {
        "schema": "spider.runtime.evidence",
        "generated-at": _now(),
        "scope": "four-runtime-online-ci-evidence",
        "evidence-mode": EVIDENCE_MODE,
        "production-complete": False,
        "production-ready": False,
        "note": "中文注释：该证据来自在线 CI manifest 归一化；工具不执行运行时命令，production-ready 仍由外部发布门禁判定。",
        "manifest": _manifest_metadata(manifest_path, state, manifest_error, manifest_payload, run_url_blockers),
        "files": files,
        "runtime-test-artifacts": runtime_artifacts,
        "runtime-artifact-summary": _runtime_summary(runtime_artifacts),
        "runtime-artifact-complete": runtime_artifact_complete,
        "completion-state": completion_state,
        "release-unblock-condition": {
            "id": "four-runtime-online-ci",
            "state": "satisfied" if runtime_artifact_complete else "blocked",
            "requires": [f"{runtime}-runtime-ci-artifact" for runtime in RUNTIMES],
            "reason": "four-runtime-online-ci-complete" if runtime_artifact_complete else "four-runtime-online-ci-incomplete",
            "blockers": blockers,
            "unblocks": ["release-go-live-runtime-ci"],
        },
        "blockers": blockers,
        "summary": {
            "runtime-count": len(RUNTIMES),
            "manifest-state": state,
            "valid-runtime-count": valid_count,
            "passed-count": passed_count,
            "failed-count": failed_count,
            "blocked-count": blocked_count,
            "missing-count": missing_count,
            "blocker-count": len(blockers),
            "runtime-artifact-complete": runtime_artifact_complete,
        },
    }


def main(argv: list[str] | None = None) -> int:
    """中文注释：CLI 入口，读取 manifest 并把 schema-valid evidence 写入 output。"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)

    payload = buildEvidence(manifestPath=args.manifest, repoRoot=args.repo_root)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
