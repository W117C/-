"""Gated tool decorator — eliminates boilerplate across all tool functions.

Every tool function follows the same pattern:
  1. Extract target from params
  2. gate.check() — authorization + blocklist + quota pre-check
  3. Create adapter + run
  4. Generate engagement_id
  5. Convert Findings → dicts + tag with engagement_id
  6. gate.commit_findings() — persist findings + decrement quota + audit
  7. Build and return the unified output dict

This decorator handles steps 1-2 and 4-7, so each tool function only
needs to write step 3 (the adapter-specific logic).
"""
from __future__ import annotations

import functools
import os
from collections import Counter
from typing import Any, Callable, Union

from secagent.binmgmt.launcher import Launcher
from secagent.core.errors import InvalidInputError
from secagent.core.finding import Finding
from secagent.core.gate import ComplianceGate

# Type: a tool function returns either list[Finding] or a dict override
ToolFn = Callable[..., Union[list[Finding], list[dict[str, Any]], dict[str, Any]]]


def _resolve_target(params: dict[str, Any], field: str | list[str]) -> str:
    """Extract a single target string from params, trying fields in order.

    Raises ``InvalidInputError`` if no target is found.
    """
    fields = [field] if isinstance(field, str) else field
    for f in fields:
        val = params.get(f)
        if val:
            if isinstance(val, str) and val:
                # Strip URL scheme for scope checks — scope is host-based
                if "://" in val:
                    from urllib.parse import urlparse
                    host = urlparse(val).hostname
                    if host:
                        return host
                return val
            if isinstance(val, list) and val:
                raw = str(val[0])
                if "://" in raw:
                    from urllib.parse import urlparse
                    host = urlparse(raw).hostname
                    if host:
                        return host
                return raw
    raise InvalidInputError(
        field=fields[0],
        reason=f"must be a non-empty value (tried fields: {', '.join(fields)})",
    )


def _summary_from_dicts(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "total": len(findings),
        "by_severity": dict(Counter(f.get("severity", "info") for f in findings)),
        "by_type": dict(Counter(f.get("type", "") for f in findings)),
    }


def _findings_to_dicts(
    findings: list,
) -> list[dict[str, Any]]:
    """Convert findings to dicts using duck-typing (supports Finding, Mock, or dict)."""
    result: list = []
    for f in findings:
        to_dict = getattr(f, "to_dict", None)
        if callable(to_dict):
            result.append(to_dict())
        else:
            result.append(dict(f))
    return result  # type: ignore[return-value]


def _tag_engagement(findings: list[dict[str, Any]], engagement_id: str) -> None:
    for fd in findings:
        fd["engagement_id"] = engagement_id


def gated_tool(
    tool_name: str,
    target_field: str | list[str],
) -> Callable[[ToolFn], ToolFn]:
    """Decorator: wraps a tool function with the compliance gate pattern.

    The decorated function receives (gate, params, authz_token, caller_id)
    and is responsible ONLY for executing the tool and returning findings
    (as ``list[Finding]`` or ``list[dict]``).

    The decorator handles:
      1. Extracting the target from params
      2. ``gate.check()`` — authorization + blocklist + quota pre-check
      3. Generating an engagement_id
      4. Converting Findings → dicts + tagging with engagement_id
      5. ``gate.commit_findings()`` — persist, quota decrement, audit
      6. Building the unified return dict

    If the decorated function returns a ``dict`` instead of a ``list``,
    it is assumed to be a pre-built return dict and is passed through
    unchanged (for special cases needing override).

    Args:
        tool_name: Canonical tool name (e.g. ``"enumerate_subdomains"``).
        target_field: Key(s) in ``params`` to extract the target from.
                      A string (e.g. ``"target_domain"``) or a list to try
                      in order (e.g. ``["target", "scope"]``).
    """

    def decorator(fn: ToolFn) -> ToolFn:
        @functools.wraps(fn)
        def wrapper(
            *,
            gate: ComplianceGate,
            params: dict[str, Any],
            authz_token: str,
            caller_id: str = "unknown",
            **kwargs: Any,
        ) -> dict[str, Any]:
            # Step 1: extract target
            target = _resolve_target(params, target_field)

            # Step 2: gate pre-flight check
            scope = gate.check(
                token=authz_token,
                tool=tool_name,
                target=target,
                caller_id=caller_id,
            )

            # Step 3: run the tool function (adapter-specific logic)
            result = fn(
                gate=gate,
                params=params,
                authz_token=authz_token,
                caller_id=caller_id,
                **kwargs,
            )

            # If the function returned a full dict, it's an override — pass through
            if isinstance(result, dict):
                return result

            # Step 4: generate engagement_id + convert findings
            engagement_id = f"eng_{__import__('uuid').uuid4().hex}"
            findings_list = list(result) if result is not None else []
            findings_dicts = _findings_to_dicts(findings_list)
            _tag_engagement(findings_dicts, engagement_id)

            # Step 5: commit findings + quota + audit
            gate.commit_findings(
                token=authz_token,
                count=len(findings_dicts),
                quota_used=1,
                caller_id=caller_id,
                tool=tool_name,
                target=target,
                scope_value=scope.value,
                findings=findings_dicts,
            )

            # Step 6: build unified return dict
            finding_objs = [f for f in findings_list if isinstance(f, Finding)]
            summary = (
                Finding.summary(finding_objs)
                if finding_objs
                else _summary_from_dicts(findings_dicts)
            )

            return {
                "engagement_id": engagement_id,
                "tool": tool_name,
                "findings": findings_dicts,
                "summary": summary,
                "quota_used": 1,
            }

        return wrapper

    return decorator


def standard_adapter_tool(
    tool_name: str,
    target_field: str | list[str],
    adapter_cls: type,
    adapter_kwargs_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
) -> Callable:
    """Convenience: like ``@gated_tool`` but auto-creates the adapter.

    The decorated function's return value is **ignored** — the adapter
    is constructed and run automatically. The function signature is
    ``(gate, params, authz_token, caller_id)`` and it may mutate
    ``params`` before the adapter runs (e.g. clamping values).

    If ``adapter_kwargs_fn`` is provided, it receives ``params`` and
    returns extra kwargs for the adapter constructor (e.g.
    ``{"wordlists_dir": ...}``).
    """

    def decorator(fn: ToolFn) -> ToolFn:
        @functools.wraps(fn)
        def wrapper(
            *,
            gate: ComplianceGate,
            params: dict[str, Any],
            authz_token: str,
            caller_id: str = "unknown",
            **kwargs: Any,
        ) -> dict[str, Any]:
            # Let the fn mutate params first (safety clamps, validation)
            fn(
                gate=gate,
                params=params,
                authz_token=authz_token,
                caller_id=caller_id,
                **kwargs,
            )

            target = _resolve_target(params, target_field)
            scope = gate.check(
                token=authz_token,
                tool=tool_name,
                target=target,
                caller_id=caller_id,
            )

            binaries_dir = os.environ.get(
                "SECAGENT_BINARIES_DIR", gate.store.db_path.rsplit("/", 1)[0] + "/bin"
                if hasattr(gate, "store")
                else "./bin"
            )
            extra_kwargs = adapter_kwargs_fn(params) if adapter_kwargs_fn else {}
            adapter = adapter_cls(
                launcher=Launcher(timeout_sec=params.get("timeout_sec", 120)),
                binaries_dir=binaries_dir,
                **extra_kwargs,
            )
            findings = adapter.run(params)

            engagement_id = f"eng_{__import__('uuid').uuid4().hex}"
            findings_list = list(findings) if findings else []
            findings_dicts = _findings_to_dicts(findings_list)
            _tag_engagement(findings_dicts, engagement_id)

            gate.commit_findings(
                token=authz_token,
                count=len(findings_dicts),
                quota_used=1,
                caller_id=caller_id,
                tool=tool_name,
                target=target,
                scope_value=scope.value,
                findings=findings_dicts,
            )

            finding_objs = [f for f in findings_list if isinstance(f, Finding)]
            summary = (
                Finding.summary(finding_objs)
                if finding_objs
                else _summary_from_dicts(findings_dicts)
            )

            return {
                "engagement_id": engagement_id,
                "tool": tool_name,
                "findings": findings_dicts,
                "summary": summary,
                "quota_used": 1,
            }

        return wrapper

    return decorator
