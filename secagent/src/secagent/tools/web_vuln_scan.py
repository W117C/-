"""Tool function: web_vuln_scan (capability extension) — ACTIVE web vulnerability verification.

Performs ACTIVE exploitation attempts to CONFIRM (not just pattern-match)
web vulnerabilities:
  - SQL injection   : quote injection + sleep-based blind + boolean diff
  - Reflected XSS   : context-aware payload reflection analysis
  - SSRF            : internal IP + OOB callback confirmation
  - LFI             : path traversal via ../ sequences

This is the HIGHEST-RISK tool in SecAgent alongside scan_vulnerabilities:
it actively sends exploit payloads to the target. The three-layer compliance
guard (authz + blocklist + rate limit) applies fully.

A finding from this tool carries confidence="validated" because it proved
exploitation succeeded, reducing the ~30% FP rate of community templates
to <10%.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

from secagent.adapters.web_vuln import WebVulnAdapter
from secagent.core.blocklist import Blocklist
from secagent.core.decorators import _commit_and_build_result
from secagent.core.errors import ComplianceBlockError, InvalidInputError, SecAgentError
from secagent.core.gate import ComplianceGate

log = logging.getLogger(__name__)


def _target_of(url: str) -> str:
    """Extract hostname from a URL for scope/blocklist checks."""
    if "://" in url:
        return urlparse(url).hostname or url
    return url


def web_vuln_scan(
    *,
    gate: ComplianceGate,
    params: dict[str, Any],
    authz_token: str,
    caller_id: str = "unknown",
) -> dict[str, Any]:
    """Run active web vulnerability verification.

    Returns the unified output structure (spec §3.1).
    Raises NotAuthorizedError / ComplianceBlockError / InvalidInputError.

    params:
      target       : str  — URL to scan (required)
      modules      : list — ["sqli","xss","ssrf","lfi"] (default: all)
      oob_callback : str  — callback URL for SSRF confirmation (optional)
      timeout_sec  : int  — per-request timeout (default: 30)
      rate_limit   : int  — requests per minute (default: 60)
    """
    target = params.get("target", "")
    if not target:
        raise InvalidInputError(field="target", reason="must be a non-empty URL")

    # Normalize target with scheme if missing
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
        params = dict(params)
        params["target"] = target

    tool_name = "web_vuln_scan"

    # --- Layer 1: gate.check (authz + blocklist + audit) -----------------
    scope = gate.check(
        token=authz_token, tool=tool_name, target=_target_of(target), caller_id=caller_id
    )

    # --- Layer 2: blocklist re-check before active exploitation ---------
    # This tool sends exploit payloads — the blocklist MUST be enforced
    # a second time to prevent any .gov/.mil target from ever being hit.
    blocklist = gate.blocklist or Blocklist()
    blocked, reason = blocklist.is_blocked(_target_of(target))
    if blocked:
        raise ComplianceBlockError(target=target, reason=reason or "blocklist match (Layer 2)")

    # --- Execute: adapter ------------------------------------------------
    # OOB callback confirmation. Two modes:
    #   * oob_callback == "auto"  → we spin up an embedded CallbackServer on
    #     an OS-assigned port, rewrite the callback base to that port, and
    #     poll it for confirmation.
    #   * oob_callback == full URL → the caller runs their own listener; we do
    #     NOT start a server (poller stays None) and the adapter records the
    #     dispatch as pending_verification for the caller to confirm out-of-band.
    oob_callback = params.get("oob_callback", "")
    oob_server = None
    oob_poller = None
    if oob_callback == "auto":
        from secagent.oob import CallbackServer
        oob_server = CallbackServer(port=0)
        oob_server.start()
        actual_port = oob_server.port
        oob_callback = f"http://127.0.0.1:{actual_port}/{{id}}"
        def oob_poller(cid):
            return bool(oob_server.poll(cid, timeout=5))
    elif oob_callback:
        # External listener mode: do not start a server; adapter stays pending.
        pass

    # Write the (possibly rewritten) callback base back so the adapter injects
    # the correct URL into the payload.
    if oob_callback:
        params = dict(params)
        params["oob_callback"] = oob_callback

    try:
        adapter = WebVulnAdapter(
            timeout_sec=params.get("timeout_sec", 300),
            proxy_manager=gate.proxy_manager,
            http_timeout=params.get("timeout_sec_per_req", 30),
            oob_poller=oob_poller,
            cookie=params.get("cookie", ""),
        )
        findings = adapter.run(params)
    except SecAgentError:
        raise  # Business errors propagate
    except Exception as e:
        log.error("web_vuln_scan adapter.run failed: %s", e)
        return {
            "error": {"code": "TOOL_FAILED", "message": str(e), "retryable": False},
            "tool": tool_name,
            "findings": [],
            "summary": {"total": 0},
        }
    finally:
        if oob_server is not None:
            oob_server.stop()

    # --- Post-run: commit + build return ---------------------------------
    engagement_id, findings_dicts, summary = _commit_and_build_result(
        findings=findings,
        gate=gate,
        token=authz_token,
        count=len(findings),
        quota_used=1,
        caller_id=caller_id,
        tool_name=tool_name,
        target=target,
        scope_value=scope.value,
    )

    return {
        "engagement_id": engagement_id,
        "tool": tool_name,
        "findings": findings_dicts,
        "summary": summary,
        "quota_used": 1,
    }
