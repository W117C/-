# 中文注释：本文件属于 Mond Spider Agent / 四框架爬虫系统。
# 中文注释：所属模块：测试与验收。
# 中文注释：用途说明：该文件参与爬虫任务定义、调度、执行、抽取、运行时适配或测试支撑。
# 中文注释：维护提示：修改逻辑时请同步运行相关 smoke/test，确认 Mond Spider Agent 与四个爬虫框架链路仍可用。
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
TOOL = ROOT / "tools" / "fourruntimeonlinecievidence.py"
MANIFEST_TOOL = ROOT / "tools" / "four-runtime-ci-manifest-from-artifacts.py"
SCHEMA = ROOT / "contracts" / "four-runtime-online-ci-evidence.schema.json"
RUNTIMES = ("python", "go", "rust", "java")


def loadTool():
    spec = importlib.util.spec_from_file_location("fourruntimeonlinecievidence", TOOL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def loadManifestTool():
    spec = importlib.util.spec_from_file_location("four_runtime_ci_manifest_from_artifacts", MANIFEST_TOOL)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def assertHyphenKeys(payload: Any) -> None:
    if isinstance(payload, dict):
        for key, value in payload.items():
            assert "_" not in key
            assertHyphenKeys(value)
    elif isinstance(payload, list):
        for item in payload:
            assertHyphenKeys(item)


def writeArtifact(root: Path, runtime: str) -> str:
    path = root / "ci-artifacts" / f"{runtime}-runtime-ci.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "spider.runtime-ci.artifact",
                "runtime": runtime,
                "status": "passed",
                "command": "recorded by online ci",
                "version": "test",
                "artifact-paths": [str(path)],
            }
        ),
        encoding="utf-8",
    )
    return str(path.relative_to(root)).replace("\\", "/")


def writeRuntimeCiArtifact(path: Path, runtime: str, command: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "schema": "spider.runtime-ci.artifact",
                "runtime": runtime,
                "status": "passed",
                "command": command or f"{runtime} runtime ci",
                "version": "test",
                "artifact-paths": [str(path)],
                "duration-ms": 1000,
                "exit-code": 0,
            }
        ),
        encoding="utf-8",
    )


def writeManifest(
    root: Path,
    overrides: dict[str, dict[str, Any]] | None = None,
    runUrl: str = "https://github.com/test-org/spider/actions/runs/123456",
) -> Path:
    overrides = overrides or {}
    commands = {
        "python": "python -m pytest tests -q",
        "go": "go test ./...",
        "rust": "cargo test --manifest-path rustspider/Cargo.toml",
        "java": "mvn -f javaspider/pom.xml test",
    }
    artifacts = []
    for index, runtime in enumerate(RUNTIMES, start=1):
        item = {
            "runtime": runtime,
            "status": "passed",
            "command": commands[runtime],
            "duration-ms": index * 1000,
            "exit-code": 0,
            "artifact-paths": [writeArtifact(root, runtime)],
        }
        item.update(overrides.get(runtime, {}))
        artifacts.append(item)

    manifest = {
        "schema": "spider.ci.artifact-manifest",
        "ci-provider": "test-ci",
        "run-id": "run-123",
        "run-url": runUrl,
        "artifacts": artifacts,
    }
    path = root / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def test_missing_manifest_is_blocked_without_production_ready(tmp_path: Path) -> None:
    tool = loadTool()

    payload = tool.buildEvidence(manifestPath=tmp_path / "missing.json", repoRoot=tmp_path)

    assert payload["schema"] == "spider.runtime.evidence"
    assert payload["scope"] == "four-runtime-online-ci-evidence"
    assert payload["manifest"]["state"] == "missing"
    assert payload["production-complete"] is False
    assert payload["production-ready"] is False
    assert payload["runtime-artifact-complete"] is False
    assert payload["completion-state"] == "blocked"
    assert "ci-artifact-manifest-missing" in payload["blockers"]
    assert payload["release-unblock-condition"]["state"] == "blocked"
    assert payload["release-unblock-condition"]["reason"] == "four-runtime-online-ci-incomplete"
    assert {item["status"] for item in payload["runtime-test-artifacts"]} == {"blocked"}


def test_valid_real_manifest_completes_runtime_artifact_evidence(tmp_path: Path) -> None:
    tool = loadTool()
    manifest = writeManifest(tmp_path)

    payload = tool.buildEvidence(manifestPath=manifest, repoRoot=tmp_path)

    assert payload["manifest"]["state"] == "present"
    assert payload["manifest"]["ci-provider"] == "test-ci"
    assert payload["completion-state"] == "complete"
    assert payload["runtime-artifact-complete"] is True
    assert payload["production-ready"] is False
    assert payload["blockers"] == []
    assert payload["release-unblock-condition"] == {
        "id": "four-runtime-online-ci",
        "state": "satisfied",
        "requires": [
            "python-runtime-ci-artifact",
            "go-runtime-ci-artifact",
            "rust-runtime-ci-artifact",
            "java-runtime-ci-artifact",
        ],
        "reason": "four-runtime-online-ci-complete",
        "blockers": [],
        "unblocks": ["release-go-live-runtime-ci"],
    }
    assert payload["summary"]["passed-count"] == 4
    assert [item["runtime"] for item in payload["files"]] == list(RUNTIMES)
    assert all(item["duration-ms"] > 0 for item in payload["files"])
    assert all(item["exit-code"] == 0 for item in payload["files"])
    assert all(item["artifact-state"] == "present" for item in payload["runtime-test-artifacts"])


def test_manifest_generator_builds_artifacts_array_from_downloaded_artifact_dir(tmp_path: Path) -> None:
    evidenceTool = loadTool()
    manifestTool = loadManifestTool()
    artifactRoot = tmp_path / "downloaded-github-artifacts" / "spider-runtime-ci-artifacts"
    commands = {
        "python": "python -m pytest tests/testfourruntimeonlinecievidence.py -q",
        "go": "go test ./...",
        "rust": "cargo test --manifest-path rustspider/Cargo.toml",
        "java": "mvn -f javaspider/pom.xml test",
    }
    for runtime in RUNTIMES:
        writeRuntimeCiArtifact(artifactRoot / f"{runtime}-runtime-ci.json", runtime, commands[runtime])

    manifest = manifestTool.buildManifest(
        artifactRoot=tmp_path / "downloaded-github-artifacts",
        repoRoot=tmp_path,
        ciProvider="github-actions",
        runId="123456",
        runUrl="https://github.com/test-org/spider/actions/runs/123456",
    )

    assert manifest["schema"] == "spider.ci.artifact-manifest"
    assert "runtime-results" not in manifest
    assert [item["runtime"] for item in manifest["artifacts"]] == list(RUNTIMES)
    assert all(item["artifact-paths"][0].endswith(f"{item['runtime']}-runtime-ci.json") for item in manifest["artifacts"])

    manifestPath = tmp_path / "four-runtime-online-ci-manifest.json"
    manifestPath.write_text(json.dumps(manifest), encoding="utf-8")
    payload = evidenceTool.buildEvidence(manifestPath=manifestPath, repoRoot=tmp_path)

    assert payload["completion-state"] == "complete"
    assert payload["runtime-artifact-complete"] is True
    assert payload["production-ready"] is False


def test_manifest_generator_cli_writes_artifacts_array(tmp_path: Path) -> None:
    commands = {
        "python": "python -m pytest tests/testfourruntimeonlinecievidence.py -q",
        "go": "go test ./...",
        "rust": "cargo test --manifest-path rustspider/Cargo.toml",
        "java": "mvn -f javaspider/pom.xml test",
    }
    artifactRoot = tmp_path / "runtime-ci"
    for runtime in RUNTIMES:
        writeRuntimeCiArtifact(artifactRoot / f"{runtime}-runtime-ci.json", runtime, commands[runtime])
    output = tmp_path / "manifest.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(MANIFEST_TOOL),
            "--artifact-root",
            str(artifactRoot),
            "--repo-root",
            str(tmp_path),
            "--ci-provider",
            "github-actions",
            "--run-id",
            "123456",
            "--run-url",
            "https://github.com/test-org/spider/actions/runs/123456",
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert "artifacts" in payload
    assert "runtime-results" not in payload
    assert payload["summary"]["artifact-count"] == 4


def test_old_runtime_results_manifest_is_explicitly_rejected(tmp_path: Path) -> None:
    tool = loadTool()
    manifest = tmp_path / "old-runtime-results.json"
    manifest.write_text(
        json.dumps(
            {
                "schema": "spider.ci.artifact-manifest",
                "ci-provider": "test-ci",
                "run-id": "run-123",
                "run-url": "https://github.com/test-org/spider/actions/runs/123456",
                "runtime-results": [],
            }
        ),
        encoding="utf-8",
    )

    payload = tool.buildEvidence(manifestPath=manifest, repoRoot=tmp_path)

    assert payload["manifest"]["state"] == "invalid"
    assert payload["manifest"]["error"] == "runtime-results-deprecated-use-artifacts"
    assert payload["manifest"]["has-runtime-results"] is True
    assert "ci-artifact-manifest-runtime-results-deprecated" in payload["blockers"]
    assert payload["runtime-artifact-complete"] is False


def test_missing_runtime_artifact_from_generated_manifest_is_blocked(tmp_path: Path) -> None:
    evidenceTool = loadTool()
    manifestTool = loadManifestTool()
    artifactRoot = tmp_path / "runtime-ci"
    writeRuntimeCiArtifact(artifactRoot / "python-runtime-ci.json", "python", "python -m pytest tests/testfourruntimeonlinecievidence.py -q")
    writeRuntimeCiArtifact(artifactRoot / "go-runtime-ci.json", "go", "go test ./...")
    writeRuntimeCiArtifact(artifactRoot / "rust-runtime-ci.json", "rust", "cargo test --manifest-path rustspider/Cargo.toml")
    manifest = manifestTool.buildManifest(
        artifactRoot=artifactRoot,
        repoRoot=tmp_path,
        ciProvider="github-actions",
        runId="123456",
        runUrl="https://github.com/test-org/spider/actions/runs/123456",
    )
    manifestPath = tmp_path / "manifest.json"
    manifestPath.write_text(json.dumps(manifest), encoding="utf-8")

    payload = evidenceTool.buildEvidence(manifestPath=manifestPath, repoRoot=tmp_path)

    assert payload["runtime-artifact-complete"] is False
    assert payload["completion-state"] == "partial"
    assert "java:manifest-runtime-item-missing" in payload["blockers"]
    assert payload["summary"]["valid-runtime-count"] == 3


def test_manifest_blocks_placeholder_example_and_invalid_run_urls(tmp_path: Path) -> None:
    tool = loadTool()
    cases = [
        ("https://github.com/test-org/spider/actions/runs/{run-id}", "ci-run-url-placeholder"),
        ("https://ci.example.test/run-123", "ci-run-url-example"),
        ("not-a-url", "ci-run-url-invalid"),
    ]

    for index, (runUrl, blocker) in enumerate(cases):
        root = tmp_path / f"case-{index}"
        root.mkdir()
        manifest = writeManifest(root, runUrl=runUrl)

        payload = tool.buildEvidence(manifestPath=manifest, repoRoot=root)

        assert payload["runtime-artifact-complete"] is False
        assert blocker in payload["blockers"]
        assert blocker in payload["manifest"]["run-url-errors"]
        assert payload["production-ready"] is False


def test_manifest_validation_blocks_bad_command_duration_exit_and_paths(tmp_path: Path) -> None:
    tool = loadTool()
    manifest = writeManifest(
        tmp_path,
        {
            "python": {"command": "echo ok"},
            "go": {"duration-ms": 0},
            "rust": {"exit-code": 1},
            "java": {"artifact-paths": ["ci-artifacts/missing-java-runtime-ci.json"]},
        },
    )

    payload = tool.buildEvidence(manifestPath=manifest, repoRoot=tmp_path)

    assert payload["completion-state"] == "blocked"
    assert payload["runtime-artifact-complete"] is False
    assert payload["summary"]["valid-runtime-count"] == 0
    blockers = "\n".join(payload["blockers"])
    assert "python:command-does-not-match-runtime-ci-contract" in blockers
    assert "go:duration-ms-missing-or-nonpositive" in blockers
    assert "rust:exit-code-nonzero" in blockers
    assert "java:artifact-paths-missing-on-disk:ci-artifacts/missing-java-runtime-ci.json" in blockers


def test_schema_accepts_missing_and_complete_payloads(tmp_path: Path) -> None:
    tool = loadTool()
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)

    missingPayload = tool.buildEvidence(manifestPath=tmp_path / "missing.json", repoRoot=tmp_path)
    completePayload = tool.buildEvidence(manifestPath=writeManifest(tmp_path), repoRoot=tmp_path)

    validator = Draft202012Validator(schema)
    validator.validate(missingPayload)
    validator.validate(completePayload)
    assertHyphenKeys(missingPayload)
    assertHyphenKeys(completePayload)


def testcli_writes_json_output(tmp_path: Path) -> None:
    manifest = writeManifest(tmp_path)
    output = tmp_path / "four-runtime-online-ci-evidence.json"

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(TOOL),
            "--manifest",
            str(manifest),
            "--repo-root",
            str(tmp_path),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0
    assert completed.stdout == ""
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["schema"] == "spider.runtime.evidence"
    assert payload["completion-state"] == "complete"
