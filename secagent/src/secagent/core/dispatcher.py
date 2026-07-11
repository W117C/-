"""Agent dispatcher — dynamic parallel task execution.

DEPRECATED: This module was absorbed into ``secagent.server.app`` and
``secagent.core.decorators``. It remains here as a reference for the
parallel-dispatch pattern but is NOT imported by any production code.
Use ``submit_scan`` / ``poll_result`` for async execution instead.

Absorbed from Strix's "multi-agent orchestration" pattern.
Dispatches independent scan tasks to a thread pool, collects results,
and merges findings with dedup + enrichment.

Usage:
    dispatcher = AgentDispatcher(gate, authz_token, caller_id)
    results = dispatcher.dispatch([
        Task("scan_ports", target="example.com", ports="80,443"),
        Task("scan_vulnerabilities", targets=["https://example.com"]),
    ])
"""
from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from secagent.core.gate import ComplianceGate
from secagent.core.remediation import enrich_finding

log = logging.getLogger(__name__)


@dataclass
class Task:
    """A single scan task for the dispatcher."""
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    priority: int = 0  # higher = runs first


@dataclass
class TaskResult:
    """Result from a dispatched task."""
    tool: str
    findings: list[dict[str, Any]]
    success: bool
    error: str = ""
    quota_used: int = 0


# Registry: tool name → callable
_TOOL_REGISTRY: dict[str, Callable] = {}


def register_tool(name: str) -> Callable:
    """Decorator to register a tool function in the dispatcher registry."""
    def wrapper(fn: Callable) -> Callable:
        _TOOL_REGISTRY[name] = fn
        return fn
    return wrapper


class AgentDispatcher:
    """Dispatch scan tasks in parallel, collect and enrich results.

    Example:
        dispatcher = AgentDispatcher(gate, "auth_xxx", "cli")
        results = dispatcher.dispatch([
            Task("enumerate_subdomains", {"target_domain": "example.com"}),
            Task("scan_ports", {"target": "example.com", "ports": "80,443"}),
        ])
    """

    def __init__(
        self,
        gate: ComplianceGate,
        authz_token: str = "",
        caller_id: str = "dispatcher",
        max_workers: int = 5,
    ):
        self._gate = gate
        self._authz_token = authz_token
        self._caller_id = caller_id
        self._max_workers = max_workers

    def dispatch(self, tasks: list[Task]) -> dict[str, Any]:
        """Execute tasks in parallel (respecting priority order)."""
        if not tasks:
            return self._empty_result()

        # Sort by priority descending
        sorted_tasks = sorted(tasks, key=lambda t: -t.priority)

        all_results: list[TaskResult] = []
        seen_keys: dict[str, Task] = {}

        # Identify sequential chains (same tool, sequential dependencies mark)
        parallel_tasks = [t for t in sorted_tasks if t.tool not in seen_keys]
        seen_keys.update({t.tool: t for t in sorted_tasks})

        # Dispatch parallel
        with ThreadPoolExecutor(max_workers=min(self._max_workers, len(parallel_tasks))) as pool:
            future_map = {}
            for task in parallel_tasks:
                future = pool.submit(self._run_single, task)
                future_map[future] = task

            for future in as_completed(future_map):
                task = future_map[future]
                try:
                    result = future.result()
                    all_results.append(result)
                except Exception as exc:
                    log.error("Task %s failed: %s", task.tool, exc)
                    all_results.append(TaskResult(
                        tool=task.tool, findings=[], success=False, error=str(exc),
                    ))

        # Merge + enrich findings
        all_findings: list[dict[str, Any]] = []
        seen_dedup: set[tuple[str, str, str]] = set()
        total_quota = 0

        for result in all_results:
            total_quota += result.quota_used
            for f in result.findings:
                key = (f.get("type", ""), f.get("target", ""), f.get("title", ""))
                if key not in seen_dedup:
                    seen_dedup.add(key)
                    enrich_finding(f)
                    all_findings.append(f)

        return {
            "engagement_id": f"eng_{uuid.uuid4().hex}",
            "tool": "agent_dispatcher",
            "findings": all_findings,
            "summary": {
                "total": len(all_findings),
                "by_severity": dict(__import__("collections").Counter(
                    f.get("severity", "info") for f in all_findings
                )),
                "by_type": dict(__import__("collections").Counter(
                    f.get("type", "") for f in all_findings
                )),
            },
            "quota_used": total_quota,
            "task_results": [
                {"tool": r.tool, "success": r.success, "findings": len(r.findings),
                 "error": r.error}
                for r in all_results
            ],
        }

    def _run_single(self, task: Task) -> TaskResult:
        """Execute a single task and return its result."""
        fn = _TOOL_REGISTRY.get(task.tool)
        if fn is None:
            # Try dynamic import
            try:
                mod = __import__(
                    f"secagent.tools.{task.tool}", fromlist=[task.tool]
                )
                fn = getattr(mod, task.tool)
                _TOOL_REGISTRY[task.tool] = fn
            except (ImportError, AttributeError) as exc:
                return TaskResult(
                    tool=task.tool, findings=[], success=False,
                    error=f"unknown tool: {exc}",
                )

        try:
            result = fn(
                gate=self._gate,
                params=task.params,
                authz_token=self._authz_token,
                caller_id=self._caller_id,
            )
            if isinstance(result, dict):
                return TaskResult(
                    tool=task.tool,
                    findings=result.get("findings", []),
                    success=True,
                    quota_used=result.get("quota_used", 1),
                )
            return TaskResult(tool=task.tool, findings=[], success=True)
        except Exception as exc:
            return TaskResult(
                tool=task.tool, findings=[], success=False, error=str(exc),
            )

    def _empty_result(self) -> dict[str, Any]:
        return {
            "engagement_id": "",
            "tool": "agent_dispatcher",
            "findings": [],
            "summary": {"total": 0, "by_severity": {}, "by_type": {}},
            "quota_used": 0,
            "task_results": [],
        }
