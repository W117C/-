"""Declarative tool registry — schema + handler for each MCP tool (spec §3.2).

Adding a new tool in M3 = append one `ToolDefinition` to `all_tools()` and
write a thin handler that adapts `(gate, arguments)` to the existing tool
function signature. No changes to `app.py` or `__main__.py` needed.

Each handler receives the shared `ComplianceGate` (so authorization/blocklist/
audit/quota all flow through it) and the raw MCP arguments dict. It returns
the unified output structure (spec §3.1) on success, or raises a
`SecAgentError` subclass — `SecAgentServer.call_tool` converts those to the
unified error dict.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from secagent.core.gate import ComplianceGate


@dataclass(frozen=True)
class ToolDefinition:
    """One MCP tool: its JSON-Schema input contract and dispatch handler."""

    name: str
    description: str
    input_schema: dict[str, Any]
    handler: Callable[[ComplianceGate, dict[str, Any]], dict[str, Any]]


def _handle_enumerate_subdomains(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → enumerate_subdomains tool function (spec §3.2 ①)."""
    from secagent.tools.enumerate_subdomains import enumerate_subdomains

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target_domain": args.get("target_domain", ""),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    sources = args.get("sources")
    if sources:
        params["sources"] = sources

    return enumerate_subdomains(
        gate=gate,
        params=params,
        authz_token=authz_token,
        caller_id=caller_id,
    )


_ENUMERATE_SUBDOMAINS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target_domain": {
            "type": "string",
            "description": (
                "Root domain to enumerate subdomains for (e.g. 'acme.com'). "
                "Must be within the scope of the supplied authz_token."
            ),
        },
        "authz_token": {
            "type": "string",
            "description": (
                "Authorization token issued via `secagent authz add` and "
                "verified via `secagent authz verify`. The token's scope must "
                "cover target_domain; otherwise NOT_AUTHORIZED is returned."
            ),
        },
        "sources": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Optional list of subfinder passive sources (e.g. "
                "['crtsh','virustotal']). Defaults to subfinder's full source set."
            ),
        },
        "timeout_sec": {
            "type": "integer",
            "default": 120,
            "description": "Subprocess timeout in seconds.",
        },
        "caller_id": {
            "type": "string",
            "description": (
                "Optional caller identifier written to the audit log. "
                "Defaults to 'mcp-client'."
            ),
        },
    },
    "required": ["target_domain", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑨ scan_ports (async)
# ---------------------------------------------------------------------------

def _handle_scan_ports(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → scan_ports tool function."""
    from secagent.tools.scan_ports import scan_ports

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target": args.get("target", ""),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    for opt in ("ports", "scan_type", "rate"):
        if args.get(opt) is not None:
            params[opt] = args[opt]

    return scan_ports(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_SCAN_PORTS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Domain or IP to scan for open ports. Must be within the "
                "authz_token scope."
            ),
        },
        "authz_token": {"type": "string"},
        "ports": {
            "type": "string",
            "description": "Port range to scan (e.g. '80,443,8080-8090'). Default: '80,443,8080-8090,8443'.",
        },
        "scan_type": {
            "type": "string",
            "default": "connect",
            "description": "'connect' (no root) or 'syn' (requires CAP_NET_RAW).",
        },
        "rate": {
            "type": "integer",
            "default": 500,
            "description": "Scan rate in packets/second. Capped at 2000.",
        },
        "timeout_sec": {"type": "integer", "default": 120},
        "caller_id": {"type": "string"},
    },
    "required": ["target", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑩ discover_paths (async)
# ---------------------------------------------------------------------------

def _handle_discover_paths(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → discover_paths tool function."""
    from secagent.tools.discover_paths import discover_paths

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target": args.get("target", ""),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    for opt in ("wordlist", "extensions", "recursive", "recursive_depth",
                 "match_status", "threads", "rate"):
        if args.get(opt) is not None:
            params[opt] = args[opt]

    return discover_paths(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_DISCOVER_PATHS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "URL to fuzz (e.g. 'https://example.com/FUZZ'). The host must be "
                "within the authz_token scope."
            ),
        },
        "authz_token": {"type": "string"},
        "wordlist": {
            "type": "string",
            "default": "builtin",
            "description": "Wordlist path or key: 'builtin' (L1, ~1200 paths), 'common' (L2, ~5000), or a custom path.",
        },
        "extensions": {
            "type": "string",
            "description": "File extensions to append (e.g. 'php,asp,js,bak').",
        },
        "recursive": {"type": "boolean", "default": False},
        "recursive_depth": {"type": "integer", "default": 1, "description": "Recursion depth, max 3."},
        "match_status": {"type": "string", "description": "Status codes to match (e.g. '200,301,302')."},
        "threads": {"type": "integer", "default": 40, "description": "Thread count, max 200."},
        "rate": {"type": "integer", "default": 100, "description": "Requests/sec, max 500."},
        "timeout_sec": {"type": "integer", "default": 120},
        "caller_id": {"type": "string"},
    },
    "required": ["target", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑪ passive_recon (sync)
# ---------------------------------------------------------------------------

def _handle_passive_recon(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → passive_recon tool function."""
    from secagent.tools.passive_recon import passive_recon

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target": args.get("target", ""),
    }
    if args.get("sources") is not None:
        params["sources"] = args["sources"]

    return passive_recon(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_PASSIVE_RECON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Domain to gather passive intelligence on (e.g. 'example.com'). "
                "Must be within the authz_token scope."
            ),
        },
        "authz_token": {"type": "string"},
        "sources": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Sources to query: 'crtsh', 'securitytrails', 'shodan'. Default: all.",
        },
        "caller_id": {"type": "string"},
    },
    "required": ["target", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑦ submit_scan (async)
# ---------------------------------------------------------------------------

_SUBMIT_SCAN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "tool": {
            "type": "string",
            "description": (
                "Tool to run asynchronously. One of: attack_surface_scan, "
                "probe_services, gather_osint, scan_vulnerabilities, "
                "scan_ports, discover_paths."
            ),
        },
        "params": {
            "type": "object",
            "description": (
                "Parameters dict passed to the tool. See individual tool "
                "schemas for expected fields."
            ),
        },
        "authz_token": {
            "type": "string",
            "description": "Verified authorization token covering the target(s).",
        },
        "caller_id": {
            "type": "string",
            "description": "Optional caller identifier for the audit log.",
        },
    },
    "required": ["tool", "params", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑧ poll_result (async)
# ---------------------------------------------------------------------------

_POLL_RESULT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "job_id": {
            "type": "string",
            "description": "Job ID returned by submit_scan.",
        },
    },
    "required": ["job_id"],
}


# ---------------------------------------------------------------------------
# ⑫ check_health (sync, no auth required)
# ---------------------------------------------------------------------------

_CHECK_HEALTH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "required": [],
}


def _handle_check_health(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → check_health tool function."""
    from secagent.tools.check_health import check_health
    return check_health(gate=gate, params=args, authz_token=None, caller_id="system")


def all_tools() -> list[ToolDefinition]:
    """Return every tool currently exposed over MCP.

    Fast tools are exposed synchronously. Slow tools (attack_surface_scan,
    probe_services, gather_osint, scan_vulnerabilities, scan_ports,
    discover_paths) use submit_scan / poll_result instead to avoid MCP timeout.
    """
    return [
        ToolDefinition(
            name="enumerate_subdomains",
            description=(
                "Enumerate subdomains of an authorized domain using subfinder "
                "(passive sources only, read-only — no packets sent to the "
                "target). Returns unified Finding objects of type 'subdomain'."
            ),
            input_schema=_ENUMERATE_SUBDOMAINS_SCHEMA,
            handler=_handle_enumerate_subdomains,
        ),
        ToolDefinition(
            name="scan_secret_leaks",
            description=(
                "Scan an authorized repository (local path or github.com/owner/"
                "repo) for leaked credentials using gitleaks. Read-only. "
                "Returns Findings of type 'secret_leak' with severity critical/"
                "high. Secrets are REDACTED before storage (data-minimization, "
                "spec §4.3) — only the first/last 4 chars are kept."
            ),
            input_schema=_SCAN_SECRET_LEAKS_SCHEMA,
            handler=_handle_scan_secret_leaks,
        ),
        ToolDefinition(
            name="crawl_target",
            description=(
                "Crawl an authorized target URL with a built-in static HTTP "
                "crawler and extract exposure signals: HTML forms, JS API "
                "endpoints, email addresses, and suspicious secrets in HTML "
                "comments. Read-only (GET requests). Returns Findings of type "
                "'exposure'."
            ),
            input_schema=_CRAWL_TARGET_SCHEMA,
            handler=_handle_crawl_target,
        ),
        ToolDefinition(
            name="passive_recon",
            description=(
                "Gather passive intelligence on an authorized domain from "
                "multiple public sources (crt.sh, SecurityTrails, Shodan). "
                "No packets sent to the target. Returns Findings of type 'intel'."
            ),
            input_schema=_PASSIVE_RECON_SCHEMA,
            handler=_handle_passive_recon,
        ),
        ToolDefinition(
            name="check_health",
            description=(
                "Run a comprehensive health check on the SecAgent environment. "
                "Reports database connectivity, binary availability, wordlist "
                "status, and system capabilities. NO authz_token required — "
                "this is a diagnostic tool, not a scan."
            ),
            input_schema=_CHECK_HEALTH_SCHEMA,
            handler=_handle_check_health,
        ),
        ToolDefinition(
            name="decode_value",
            description=(
                "Auto-detect encoding and decode data. Supports base64, hex, "
                "URL, JWT, timestamps, and hash computation. For reversing "
                "encoded payloads found in JS, API responses, or network traffic."
            ),
            input_schema=_DECODE_VALUE_SCHEMA,
            handler=_handle_decode_value,
        ),
        ToolDefinition(
            name="analyze_web",
            description=(
                "Analyze web artifacts: JS deobfuscation, API signature analysis, "
                "header/WAF fingerprinting, and URL parameter inspection."
            ),
            input_schema=_ANALYZE_WEB_SCHEMA,
            handler=_handle_analyze_web,
        ),
        ToolDefinition(
            name="inspect_token",
            description=(
                "Inspect authentication tokens: JWT decode, cookie analysis, "
                "token type detection, and security assessment."
            ),
            input_schema=_INSPECT_TOKEN_SCHEMA,
            handler=_handle_inspect_token,
        ),
        ToolDefinition(
            name="analyze_binary",
            description=(
                "Analyze native binaries: structure inspection (PE/ELF/Mach-O), "
                "symbol-aware disassembly, string extraction, and packing "
                "detection. Supports analyze/disasm/strings/packing operations."
            ),
            input_schema=_ANALYZE_BINARY_SCHEMA,
            handler=_handle_analyze_binary,
        ),
    ]


# ---------------------------------------------------------------------------
# ② probe_services
# ---------------------------------------------------------------------------

def _handle_probe_services(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → probe_services tool function (spec §3.2 ②)."""
    from secagent.tools.probe_services import probe_services

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "targets": args.get("targets", []),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    ports = args.get("ports")
    if ports:
        params["ports"] = ports
    threads = args.get("threads")
    if threads:
        params["threads"] = threads

    return probe_services(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_PROBE_SERVICES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "List of domains/IPs to probe (e.g. ['sub.acme.com','1.2.3.4']). "
                "Every entry must be within the authz_token scope."
            ),
        },
        "authz_token": {
            "type": "string",
            "description": "Verified authorization token covering all targets.",
        },
        "ports": {
            "type": "string",
            "description": "Optional comma-separated port list (e.g. '80,443,8080').",
        },
        "threads": {
            "type": "integer",
            "description": "Optional httpx thread count.",
        },
        "timeout_sec": {"type": "integer", "default": 120},
        "caller_id": {"type": "string"},
    },
    "required": ["targets", "authz_token"],
}


# ---------------------------------------------------------------------------
# ④ gather_osint
# ---------------------------------------------------------------------------

def _handle_gather_osint(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → gather_osint tool function (spec §3.2 ④)."""
    from secagent.tools.gather_osint import gather_osint

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target": args.get("target", ""),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    data_types = args.get("data_types")
    if data_types:
        params["data_types"] = data_types

    return gather_osint(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_GATHER_OSINT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Domain or email to gather OSINT on (e.g. 'acme.com'). "
                "Must be within the authz_token scope."
            ),
        },
        "authz_token": {"type": "string"},
        "data_types": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Optional filter: ['emails','subdomains','hosts','usernames'].",
        },
        "timeout_sec": {"type": "integer", "default": 120},
        "caller_id": {"type": "string"},
    },
    "required": ["target", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑤ scan_secret_leaks
# ---------------------------------------------------------------------------

def _handle_scan_secret_leaks(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → scan_secret_leaks tool function (spec §3.2 ⑤)."""
    from secagent.tools.scan_secret_leaks import scan_secret_leaks

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "scope": args.get("scope", ""),
        "timeout_sec": args.get("timeout_sec", 120),
    }
    mode = args.get("mode")
    if mode:
        params["mode"] = mode

    return scan_secret_leaks(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_SCAN_SECRET_LEAKS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "scope": {
            "type": "string",
            "description": (
                "Repository to scan: local path ('/path/to/repo') or "
                "'github.com/owner/repo'. Must be within the authz_token's "
                "REPO scope."
            ),
        },
        "authz_token": {"type": "string"},
        "mode": {
            "type": "string",
            "default": "github",
            "description": "MVP only supports 'github' (local repo scan).",
        },
        "timeout_sec": {"type": "integer", "default": 120},
        "caller_id": {"type": "string"},
    },
    "required": ["scope", "authz_token"],
}


# ---------------------------------------------------------------------------
# ⑥ crawl_target
# ---------------------------------------------------------------------------

def _handle_crawl_target(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → crawl_target tool function (spec §3.2 ⑥)."""
    from secagent.tools.crawl_target import crawl_target

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "target": args.get("target", ""),
        "timeout_sec": args.get("timeout_sec", 30),
    }
    for opt in ("depth", "mode", "extract", "respect_robots"):
        if args.get(opt) is not None:
            params[opt] = args[opt]

    return crawl_target(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_CRAWL_TARGET_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "target": {
            "type": "string",
            "description": (
                "Absolute URL to crawl (e.g. 'https://acme.com'). The host "
                "must be within the authz_token's DOMAIN scope."
            ),
        },
        "authz_token": {"type": "string"},
        "depth": {
            "type": "integer",
            "default": 1,
            "description": "Crawl depth. MVP supports depth=1 (single page) only.",
        },
        "mode": {
            "type": "string",
            "default": "static",
            "description": "MVP only supports 'static' (no JS rendering).",
        },
        "extract": {
            "type": "array",
            "items": {"type": "string"},
            "description": "What to extract: ['forms','js_endpoints','emails','comments'].",
        },
        "respect_robots": {"type": "boolean", "default": True},
        "timeout_sec": {"type": "integer", "default": 30},
        "caller_id": {"type": "string"},
    },
    "required": ["target", "authz_token"],
}


# ---------------------------------------------------------------------------
# ③ scan_vulnerabilities (nuclei) — highest risk, three-layer guard
# ---------------------------------------------------------------------------

def _handle_scan_vulnerabilities(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Adapt MCP arguments → scan_vulnerabilities tool function (spec §3.2 ③).

    This handler adds a THIRD compliance layer on top of the gate: a final
    blocklist re-check immediately before nuclei runs (defense in depth,
    spec §3.2 ③ 三层合规防护). The tool function itself also enforces a
    per-target rate limit.
    """
    from secagent.tools.scan_vulnerabilities import scan_vulnerabilities

    authz_token = args.get("authz_token", "")
    caller_id = args.get("caller_id", "mcp-client")

    params: dict[str, Any] = {
        "targets": args.get("targets", []),
        "timeout_sec": args.get("timeout_sec", 600),
    }
    for opt in ("templates", "severity_filter", "rate_limit"):
        if args.get(opt) is not None:
            params[opt] = args[opt]

    return scan_vulnerabilities(
        gate=gate, params=params, authz_token=authz_token, caller_id=caller_id
    )


_SCAN_VULNERABILITIES_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "targets": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Targets to scan (domains/URLs). Every target must be within "
                "the authz_token scope AND pass the blocklist. Nuclei sends "
                "ACTIVE probe packets — only scan assets you own."
            ),
        },
        "authz_token": {"type": "string"},
        "templates": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Nuclei template categories (e.g. ['cves','exposures']).",
        },
        "severity_filter": {
            "type": "string",
            "description": "Only report findings >= this severity (critical/high/medium/low/info).",
        },
        "rate_limit": {
            "type": "integer",
            "default": 150,
            "description": "Max requests/sec to each target (spec §4.2 nuclei_rate_limit).",
        },
        "timeout_sec": {"type": "integer", "default": 600},
        "caller_id": {"type": "string"},
    },
    "required": ["targets", "authz_token"],
}


# ---------------------------------------------------------------------------
# Web Reverse Engineering tools (analyzers → MCP)
# ---------------------------------------------------------------------------

def _handle_decode_value(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Auto-detect encoding and decode."""
    from secagent.core.decoders import (
        detect_encoding, auto_decode, hash_text,
        analyze_timestamp, decode_jwt,
    )

    operation = args.get("operation", "auto_decode")
    data = args.get("data", "")

    if operation == "auto_decode":
        layers = auto_decode(data, max_depth=args.get("max_depth", 3))
        return {"type": "decode_result", "layers": layers, "final": layers[-1]["result"] if layers else data}
    elif operation == "detect":
        return {"type": "detect_result", "encodings": detect_encoding(data)}
    elif operation == "hash":
        algo = args.get("algorithm", "sha256")
        return {"type": "hash_result", "algorithm": algo, "hash": hash_text(data, algo)}
    elif operation == "timestamp":
        ts = analyze_timestamp(data)
        return {"type": "timestamp_result", **ts}
    elif operation == "jwt_decode":
        result = decode_jwt(data)
        return {"type": "jwt_result", "valid": result is not None, "decoded": result}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


_DECODE_VALUE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "operation": {
            "type": "string",
            "enum": ["auto_decode", "detect", "hash", "timestamp", "jwt_decode"],
            "description": "Decode operation type.",
        },
        "data": {
            "type": "string",
            "description": "Data to decode/analyze.",
        },
        "algorithm": {
            "type": "string",
            "description": "Hash algorithm for hash operation (md5/sha1/sha256/sha512).",
        },
        "max_depth": {
            "type": "integer",
            "default": 3,
            "description": "Max decode layers for auto_decode.",
        },
    },
    "required": ["operation", "data"],
}


def _handle_analyze_web(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Analyze JS code, API signatures, or HTTP headers."""
    operation = args.get("operation", "js_analyze")
    data = args.get("data", "")

    if operation == "js_analyze":
        from secagent.analyzers.js_reverser import (
            beautify, detect_obfuscation, extract_sensitive,
        )
        return {
            "type": "js_analysis",
            "obfuscation": detect_obfuscation(data),
            "sensitive": extract_sensitive(data),
            "beautified_preview": beautify(data)[:500],
        }
    elif operation == "api_signature":
        from secagent.analyzers.api_signer import (
            classify_params, detect_signature_params, build_sign_string, SignatureConfig,
        )
        import json
        params = json.loads(args.get("params_json", "{}"))
        sig_params = detect_signature_params(params)
        classified = classify_params(params)
        config = SignatureConfig(algorithm=args.get("algorithm", "md5"))
        sign_str = build_sign_string(params, config)
        return {
            "type": "api_signature",
            "signature_params": sig_params,
            "classified": classified,
            "sign_string": sign_str,
        }
    elif operation == "header_fingerprint":
        from secagent.core.headers import fingerprint_headers, parse_ua
        import json
        headers = json.loads(args.get("headers_json", "{}"))
        wafs = fingerprint_headers(headers)
        ua_info = {}
        if "User-Agent" in headers:
            ua_info = parse_ua(headers["User-Agent"])
        return {
            "type": "header_fingerprint",
            "wafs": wafs,
            "ua_info": ua_info,
        }
    elif operation == "url_params":
        from secagent.core.headers import analyze_url_params
        result = analyze_url_params(data)
        return {"type": "url_params", **result}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


_ANALYZE_WEB_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "operation": {
            "type": "string",
            "enum": ["js_analyze", "api_signature", "header_fingerprint", "url_params"],
            "description": "Analysis operation type.",
        },
        "data": {
            "type": "string",
            "description": "Data to analyze (JS code, URL, or raw text).",
        },
        "params_json": {
            "type": "string",
            "description": "JSON-encoded parameters for api_signature operation.",
        },
        "headers_json": {
            "type": "string",
            "description": "JSON-encoded HTTP headers for header_fingerprint operation.",
        },
        "algorithm": {
            "type": "string",
            "description": "Signature algorithm hint for api_signature.",
        },
    },
    "required": ["operation"],
}


def _handle_inspect_token(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Analyze cookies, JWT tokens, and authentication tokens."""
    from secagent.analyzers.cookie_analyzer import (
        detect_token_type, analyze_jwt, analyze_cookie,
        analyze_jwt_claims, assess_token_security,
    )

    operation = args.get("operation", "detect")
    token = args.get("token", "")

    if operation == "detect":
        types = detect_token_type(token)
        return {"type": "token_detect", "token_types": types}
    elif operation == "jwt":
        result = analyze_jwt(token)
        claims = {}
        if result.payload and isinstance(result.payload, dict):
            claims = analyze_jwt_claims(result.payload)
        return {
            "type": "jwt_analysis",
            "valid": result.valid_structure,
            "algorithm": result.algorithm,
            "subject": result.subject,
            "issued_at": result.issued_at,
            "claims": claims,
        }
    elif operation == "cookie":
        name = args.get("cookie_name", "")
        result = analyze_cookie(name, token)
        return {
            "type": "cookie_analysis",
            "name": result.name,
            "is_auth": result.is_auth,
            "is_session": result.is_session,
            "token_type": result.token_type,
        }
    elif operation == "security":
        result = assess_token_security(token)
        return {"type": "security_assessment", **result}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


_INSPECT_TOKEN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "operation": {
            "type": "string",
            "enum": ["detect", "jwt", "cookie", "security"],
            "description": "Token inspection operation.",
        },
        "token": {
            "type": "string",
            "description": "Token/JWT string to analyze.",
        },
        "cookie_name": {
            "type": "string",
            "description": "Cookie name (for cookie operation).",
        },
    },
    "required": ["operation", "token"],
}
# ---------------------------------------------------------------------------
# Binary reverse engineering (analyzers → MCP)
# ---------------------------------------------------------------------------

def _handle_analyze_binary(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    """Analyze binary files: structure, disassembly, strings, packing."""
    operation = args.get("operation", "analyze")
    file_path = args.get("file_path", "")

    if not file_path:
        return {"type": "error", "message": "file_path is required"}

    if operation == "analyze":
        from secagent.analyzers.binary_analyzer import analyze_binary
        return {"type": "binary_analysis", **analyze_binary(file_path)}

    elif operation == "disasm":
        from secagent.analyzers.binary_analyzer import disassemble_function
        kwargs: dict[str, Any] = {}
        if args.get("address") is not None:
            kwargs["address"] = int(args["address"])
        if args.get("symbol"):
            kwargs["symbol"] = args["symbol"]
        kwargs["count"] = args.get("count", 32)
        result = disassemble_function(file_path, **kwargs)
        return {"type": "disassembly", "instructions": result}

    elif operation == "strings":
        from secagent.analyzers.binary_analyzer import extract_strings
        result = extract_strings(
            file_path,
            min_length=args.get("min_length", 4),
            limit=args.get("limit", 500),
        )
        return {"type": "strings", "count": len(result), "strings": result}

    elif operation == "packing":
        from secagent.analyzers.binary_analyzer import detect_packing
        result = detect_packing(file_path)
        return {"type": "packing_analysis", **result}

    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


_ANALYZE_BINARY_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "operation": {
            "type": "string",
            "enum": ["analyze", "disasm", "strings", "packing"],
            "description": "Binary analysis operation type.",
        },
        "file_path": {
            "type": "string",
            "description": "Path to the binary file to analyze.",
        },
        "address": {
            "type": "integer",
            "description": "Virtual address to disassemble from (disasm operation).",
        },
        "symbol": {
            "type": "string",
            "description": "Symbol name to disassemble (disasm operation, alternative to address).",
        },
        "count": {
            "type": "integer",
            "default": 32,
            "description": "Number of instructions to disassemble.",
        },
        "min_length": {
            "type": "integer",
            "default": 4,
            "description": "Minimum string length for string extraction.",
        },
        "limit": {
            "type": "integer",
            "default": 500,
            "description": "Maximum number of strings to return.",
        },
    },
    "required": ["operation", "file_path"],
}
