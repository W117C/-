"""Tool registration for MCP server — defines schemas and handler mappings.

All 19 tools (9 scan + 4 reverse + 4 new penetration + 1 health + 1 diagnostic)
are defined here as ToolDefinition(name, input_schema, handler).
"""
from __future__ import annotations

import json
import logging
from typing import Any

from secagent.core.gate import ComplianceGate

log = logging.getLogger(__name__)


# ── Dataclass ──

class ToolDefinition:
    """MCP tool definition: name + JSON Schema + handler."""
    __slots__ = ("name", "description", "input_schema", "handler")

    def __init__(self, name: str, description: str, input_schema: dict[str, Any],
                 handler):
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.handler = handler


# ── Handlers ──

def _handle_enumerate_subdomains(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.enumerate_subdomains import enumerate_subdomains
    return enumerate_subdomains(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_scan_ports(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.scan_ports import scan_ports
    return scan_ports(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_discover_paths(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.discover_paths import discover_paths
    return discover_paths(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_passive_recon(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.passive_recon import passive_recon
    return passive_recon(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_check_health(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.check_health import check_health
    return check_health(gate=gate, params=args, authz_token=None, caller_id="system")


def _handle_probe_services(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.probe_services import probe_services
    return probe_services(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_gather_osint(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.gather_osint import gather_osint
    return gather_osint(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_scan_secret_leaks(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.scan_secret_leaks import scan_secret_leaks
    return scan_secret_leaks(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_crawl_target(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.crawl_target import crawl_target
    return crawl_target(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_scan_vulnerabilities(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.scan_vulnerabilities import scan_vulnerabilities
    return scan_vulnerabilities(gate=gate, params=args, authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_decode_value(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    operation = args.get("operation", "auto_decode")
    value = args.get("data", args.get("value", ""))
    from secagent.core.decoders import analyze_timestamp, auto_decode, decode_jwt, detect_encoding, hash_text
    if operation == "auto_decode":
        layers = auto_decode(value)
        final = layers[-1]["result"] if isinstance(layers, list) and layers and isinstance(layers[-1], dict) else value
        return {"type": "decode_result", "final": final}
    elif operation == "detect":
        encodings = detect_encoding(value)
        if hasattr(encodings, "value"):
            encodings = [encodings.value]
        elif isinstance(encodings, list):
            encodings = [e.value if hasattr(e, "value") else str(e) for e in encodings]
        return {"type": "detect_result", "encodings": encodings}
    elif operation == "hash":
        algo = args.get("algorithm", "sha256")
        result = hash_text(value, algo)
        return {"type": "hash_result", "hash": result, "algorithm": algo}
    elif operation == "jwt" or operation == "jwt_decode":
        result = decode_jwt(value)
        if result is None:
            return {"type": "jwt_result", "valid": False, "error": "invalid or truncated JWT"}
        result["valid"] = True
        return {"type": "jwt_result", **result}
    elif operation == "timestamp" or operation == "decode":
        result = analyze_timestamp(value)
        return {"type": "timestamp_result", **result}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


def _handle_analyze_web(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    operation = args.get("operation", "js_analyze")
    js_code = args.get("data", args.get("js_code", ""))
    headers_json = args.get("headers_json", "{}")

    if operation == "js_analyze":
        from secagent.analyzers.js_reverser import beautify, detect_obfuscation, extract_sensitive
        return {
            "type": "js_analysis",
            "beautified_lines": beautify(js_code).count("\n"),
            "obfuscation": [o.value if hasattr(o, "value") else str(o) for o in detect_obfuscation(js_code)],
            "sensitive": extract_sensitive(js_code),
        }
    elif operation == "header_fingerprint":
        from secagent.core.headers import fingerprint_headers
        headers = json.loads(headers_json)
        wafs = fingerprint_headers(headers)
        return {"type": "header_fingerprint", "wafs": wafs}
    elif operation == "url_params":
        from secagent.core.headers import analyze_url_params
        raw = args.get("data", args.get("params_json", ""))
        if isinstance(raw, str) and raw.startswith("{"):
            params = json.loads(raw)
        elif isinstance(raw, str):
            params = raw
        else:
            params = ""
        return {"type": "url_params", **analyze_url_params(params)}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


def _handle_inspect_token(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    operation = args.get("operation", "detect")
    token = args.get("token", "")
    from secagent.analyzers.cookie_analyzer import (
        analyze_cookie,
        analyze_jwt,
        analyze_jwt_claims,
        assess_token_security,
        detect_token_type,
    )
    if operation == "detect":
        types = detect_token_type(token)
        return {"type": "token_detect", "token_types": types}
    elif operation == "jwt":
        result = analyze_jwt(token)
        claims = {}
        if result.payload and isinstance(result.payload, dict):
            claims = analyze_jwt_claims(result.payload)
        return {"type": "jwt_analysis", "valid": result.valid_structure,
                "algorithm": result.algorithm, "subject": result.subject,
                "issued_at": result.issued_at, "claims": claims}
    elif operation == "cookie":
        name = args.get("cookie_name", "")
        result = analyze_cookie(name, token)
        return {"type": "cookie_analysis", "name": result.name,
                "is_auth": result.is_auth, "is_session": result.is_session,
                "token_type": result.token_type}
    elif operation == "security":
        result = assess_token_security(token)
        return {"type": "security_assessment", **result}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


def _handle_analyze_binary(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    operation = args.get("operation", "analyze")
    file_path = args.get("file_path", "")
    if not file_path:
        return {"type": "error", "message": "file_path is required"}
    from secagent.analyzers.binary_analyzer import analyze_binary, detect_packing, disassemble_function, extract_strings
    if operation == "analyze":
        result = analyze_binary(file_path)
        return {"type": "binary_analysis", **result.to_dict()}
    elif operation == "strings":
        min_len = int(args.get("min_length", 4))
        limit = int(args.get("limit", 500))
        result = extract_strings(file_path, min_length=min_len, limit=limit)
        return {"type": "strings", "count": len(result), "strings": result}
    elif operation == "packing":
        result = detect_packing(file_path)
        return {"type": "packing_detect", "packed": result.packed,
                "packer": result.packer, "confidence": result.confidence}
    elif operation == "disasm":
        result = disassemble_function(file_path, args.get("symbol", args.get("function", "")))
        return {"type": "disassembly", "count": len(result), "instructions": result}
    else:
        return {"type": "error", "message": f"Unknown operation: {operation}"}


# ── New penetration tool handlers ──

def _handle_attack_surface_scan(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.attack_surface_scan import attack_surface_scan
    return attack_surface_scan(gate=gate, params=args,
                               authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_crawl_with_katana(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.crawl_with_katana import crawl_with_katana
    return crawl_with_katana(gate=gate, params=args,
                             authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_resolve_dns(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.resolve_dns import resolve_dns
    return resolve_dns(gate=gate, params=args,
                       authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_fingerprint_tls(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.fingerprint_tls import fingerprint_tls
    return fingerprint_tls(gate=gate, params=args,
                           authz_token=args.get("authz_token", ""), caller_id="mcp")


def _handle_search_engines(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.search_engines import search_engines
    return search_engines(gate=gate, params=args,
                          authz_token=args.get("authz_token", ""), caller_id="mcp")


# ── New Capability: Active Web Vulnerability Verification (Phase 2) ──


def _handle_web_vuln_scan(
    gate: ComplianceGate, args: dict[str, Any]
) -> dict[str, Any]:
    from secagent.tools.web_vuln_scan import web_vuln_scan
    return web_vuln_scan(gate=gate, params=args,
                          authz_token=args.get("authz_token", ""), caller_id="mcp")


# ── Schemas ──

_ENUMERATE_SUBDOMAINS_SCHEMA = {
    "type": "object",
    "properties": {
        "target_domain": {"type": "string", "description": "Domain to enumerate subdomains for"},
        "sources": {"type": "array", "items": {"type": "string"}, "description": "Subfinder sources to use"},
        "timeout_sec": {"type": "integer", "description": "Max seconds (default 120)", "default": 120},
    },
    "required": ["target_domain"],
}

_SCAN_SECRET_LEAKS_SCHEMA = {
    "type": "object",
    "properties": {
        "scope": {"type": "string", "description": "Repo path or github.com/owner/repo to scan"},
        "mode": {"type": "string", "enum": ["github", "local"], "description": "Scan mode", "default": "github"},
        "timeout_sec": {"type": "integer", "description": "Max seconds (default 120)", "default": 120},
    },
    "required": ["scope"],
}

_CRAWL_TARGET_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "URL to crawl (must start with http:// or https://)"},
        "extract": {"type": "array", "items": {"type": "string"},
                    "description": "Extract types: forms, js_endpoints, emails, comments"},
        "timeout_sec": {"type": "integer", "description": "Max seconds (default 30)", "default": 30},
    },
    "required": ["target"],
}

_PASSIVE_RECON_SCHEMA = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "Domain to gather intelligence on"},
        "sources": {"type": "array", "items": {"type": "string"},
                    "description": "Sources: crtsh, securitytrails, shodan"},
    },
    "required": ["target"],
}

_CHECK_HEALTH_SCHEMA = {
    "type": "object",
    "properties": {},
    "required": [],
}

_DECODE_VALUE_SCHEMA = {
    "type": "object",
    "properties": {
        "operation": {"type": "string", "enum": ["auto_decode", "detect", "hash", "jwt", "jwt_decode", "timestamp"],
                      "description": "Decode operation"},
        "value": {"type": "string", "description": "Value to decode"},
        "algorithm": {"type": "string", "description": "Hash algorithm (for hash operation)"},
    },
    "required": ["operation", "value"],
}

_ANALYZE_WEB_SCHEMA = {
    "type": "object",
    "properties": {
        "operation": {"type": "string", "enum": ["js_analyze", "header_fingerprint", "url_params"],
                      "description": "Web analysis operation"},
        "js_code": {"type": "string", "description": "JavaScript code to analyze"},
        "headers_json": {"type": "string", "description": "JSON-encoded HTTP headers for fingerprint"},
        "params_json": {"type": "string", "description": "JSON-encoded URL params for analysis"},
    },
    "required": ["operation"],
}

_INSPECT_TOKEN_SCHEMA = {
    "type": "object",
    "properties": {
        "operation": {"type": "string", "enum": ["detect", "jwt", "cookie", "security"],
                      "description": "Token inspection operation"},
        "token": {"type": "string", "description": "Token/JWT string to analyze"},
        "cookie_name": {"type": "string", "description": "Cookie name (for cookie operation)"},
    },
    "required": ["operation", "token"],
}

_ANALYZE_BINARY_SCHEMA = {
    "type": "object",
    "properties": {
        "operation": {"type": "string", "enum": ["analyze", "strings", "packing", "disasm"],
                      "description": "Binary analysis operation"},
        "file_path": {"type": "string", "description": "Path to binary file"},
        "symbol": {"type": "string", "description": "Function/symbol name for disasm"},
        "min_length": {"type": "integer", "default": 4, "description": "Min string length"},
        "limit": {"type": "integer", "default": 500, "description": "Max strings to return"},
    },
    "required": ["operation", "file_path"],
}


# ── Submit/Poll schemas (used by app.py) ──

_SUBMIT_SCAN_SCHEMA = {
    "type": "object",
    "properties": {
        "tool": {"type": "string", "description": "Tool name to submit"},
        "params": {"type": "object", "description": "Tool parameters"},
        "caller_id": {"type": "string", "description": "Caller identifier"},
    },
    "required": ["tool", "params"],
}

_POLL_RESULT_SCHEMA = {
    "type": "object",
    "properties": {
        "job_id": {"type": "string", "description": "Job ID from submit_scan"},
    },
    "required": ["job_id"],
}


# ── all_tools() ──

def all_tools() -> list[ToolDefinition]:
    """Return every tool currently exposed over MCP."""
    return [
        ToolDefinition(
            name="enumerate_subdomains",
            description="Enumerate subdomains of an authorized domain using subfinder "
                        "(passive sources only, read-only — no packets sent to the target). "
                        "Returns unified Finding objects of type 'subdomain'.",
            input_schema=_ENUMERATE_SUBDOMAINS_SCHEMA,
            handler=_handle_enumerate_subdomains,
        ),
        ToolDefinition(
            name="scan_secret_leaks",
            description="Scan an authorized repository for leaked credentials using gitleaks. "
                        "Read-only. Secrets are REDACTED before storage.",
            input_schema=_SCAN_SECRET_LEAKS_SCHEMA,
            handler=_handle_scan_secret_leaks,
        ),
        ToolDefinition(
            name="crawl_target",
            description="Crawl an authorized target URL with a built-in static HTTP crawler "
                        "and extract exposure signals: HTML forms, JS API endpoints, emails, "
                        "and suspicious secrets in HTML comments.",
            input_schema=_CRAWL_TARGET_SCHEMA,
            handler=_handle_crawl_target,
        ),
        ToolDefinition(
            name="passive_recon",
            description="Gather passive intelligence on an authorized domain from multiple "
                        "public sources (crt.sh, SecurityTrails, Shodan). No packets sent "
                        "to the target.",
            input_schema=_PASSIVE_RECON_SCHEMA,
            handler=_handle_passive_recon,
        ),
        ToolDefinition(
            name="check_health",
            description="Run a comprehensive health check on the SecAgent environment. "
                        "Reports database, binaries, wordlists, and capabilities. No "
                        "authz_token required — diagnostic tool, not a scan.",
            input_schema=_CHECK_HEALTH_SCHEMA,
            handler=_handle_check_health,
        ),
        ToolDefinition(
            name="crawl_with_katana",
            description="Deep crawl an authorized URL using ProjectDiscovery katana. "
                        "Supports headless browser mode, JS rendering, configurable "
                        "depth (1-10), and extracts all crawled URLs, sources, and "
                        "HTTP methods. Production-grade alternative to crawl_target.",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "URL to crawl"},
                    "depth": {"type": "integer", "default": 3, "description": "Crawl depth (1-10)"},
                    "headless": {"type": "boolean", "default": False, "description": "Headless browser mode"},
                    "js_render": {"type": "boolean", "default": False, "description": "JS rendering for SPAs"},
                    "timeout_sec": {"type": "integer", "default": 300, "description": "Max seconds"},
                },
                "required": ["target"],
            },
            handler=_handle_crawl_with_katana,
        ),
        ToolDefinition(
            name="resolve_dns",
            description="Resolve DNS records for authorized domains using dnsx. "
                        "Extracts A/CNAME/MX records and detects wildcard DNS "
                        "configurations. Read-only.",
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "Domains to resolve"},
                    "query_types": {"type": "array", "items": {"type": "string"}, "default": ["a", "cname"], "description": "DNS query types"},
                    "wildcard_detect": {"type": "boolean", "default": True, "description": "Wildcard detection"},
                    "timeout_sec": {"type": "integer", "default": 120, "description": "Max seconds"},
                },
                "required": ["targets"],
            },
            handler=_handle_resolve_dns,
        ),
        ToolDefinition(
            name="fingerprint_tls",
            description="Probe TLS services on authorized targets using tlsx. "
                        "Extracts certificate info, JA3/JA4 fingerprints, cipher "
                        "suites, and protocol versions.",
            input_schema={
                "type": "object",
                "properties": {
                    "targets": {"type": "array", "items": {"type": "string"}, "description": "Target hosts"},
                    "ports": {"type": "array", "items": {"type": "string"}, "default": ["443", "8443"], "description": "Ports"},
                    "cert_info": {"type": "boolean", "default": True, "description": "Certificate CN/SAN"},
                    "ja3": {"type": "boolean", "default": False, "description": "JA3 hash"},
                    "ja4": {"type": "boolean", "default": False, "description": "JA4 hash"},
                    "timeout_sec": {"type": "integer", "default": 120, "description": "Max seconds"},
                },
                "required": ["targets"],
            },
            handler=_handle_fingerprint_tls,
        ),
        ToolDefinition(
            name="search_engines",
            description="Query multiple search engines (Shodan/Censys/Fofa) via uncover "
                        "for hosts matching a query. Passive only.",
            input_schema={
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "engines": {"type": "array", "items": {"type": "string"}, "default": ["shodan", "censys", "fofa"], "description": "Engines"},
                    "limit": {"type": "integer", "default": 100, "description": "Max results"},
                    "timeout_sec": {"type": "integer", "default": 120, "description": "Max seconds"},
                },
                "required": ["query"],
            },
            handler=_handle_search_engines,
        ),
        ToolDefinition(
            name="decode_value",
            description="Auto-detect encoding and decode data: base64, hex, URL, JWT, "
                        "timestamps, hash computation.",
            input_schema=_DECODE_VALUE_SCHEMA,
            handler=_handle_decode_value,
        ),
        ToolDefinition(
            name="analyze_web",
            description="Analyze web artifacts: JS deobfuscation, API signature analysis, "
                        "header/WAF fingerprinting, URL parameter inspection.",
            input_schema=_ANALYZE_WEB_SCHEMA,
            handler=_handle_analyze_web,
        ),
        ToolDefinition(
            name="inspect_token",
            description="Inspect authentication tokens: JWT decode, cookie analysis, "
                        "token type detection, and security assessment.",
            input_schema=_INSPECT_TOKEN_SCHEMA,
            handler=_handle_inspect_token,
        ),
        ToolDefinition(
            name="analyze_binary",
            description="Analyze native binaries: structure inspection (PE/ELF/Mach-O), "
                        "symbol-aware disassembly, string extraction, and packing detection.",
            input_schema=_ANALYZE_BINARY_SCHEMA,
            handler=_handle_analyze_binary,
        ),
        ToolDefinition(
            name="attack_surface_scan",
            description="Complete attack surface mapping — orchestrates 7 phases: "
                        "subdomain enumeration, port scanning, DNS resolution, "
                        "service probing, path fuzzing, TLS fingerprinting, and "
                        "vulnerability scanning. Returns aggregated findings with "
                        "per-phase breakdown.",
            input_schema={
                "type": "object",
                "properties": {
                    "target_domain": {"type": "string", "description": "Root domain to scan"},
                    "authz_token": {"type": "string", "description": "Authorization token"},
                    "max_scan_targets": {"type": "integer", "default": 25, "description": "Max hosts to forward to vuln scan"},
                    "timeout_sec": {"type": "integer", "default": 300, "description": "Per-phase timeout"},
                    "skip_port_scan": {"type": "boolean", "default": False, "description": "Skip Phase 2 (port scanning)"},
                    "skip_dns_resolve": {"type": "boolean", "default": False, "description": "Skip Phase 2.5 (DNS resolution)"},
                    "skip_path_fuzz": {"type": "boolean", "default": True, "description": "Skip Phase 4 (path fuzzing)"},
                    "skip_tls_fingerprint": {"type": "boolean", "default": True, "description": "Skip Phase 4.5 (TLS fingerprint)"},
                    "sources": {"type": "array", "items": {"type": "string"}, "description": "Subfinder sources"},
                    "ports": {"type": "string", "default": "80,443,8080-8090,8443", "description": "Port range for scanning"},
                },
                "required": ["target_domain"],
            },
            handler=_handle_attack_surface_scan,
        ),
        ToolDefinition(
            name="web_vuln_scan",
            description="Active web vulnerability verification — SQLi (error/time/boolean-based), "
                        "XSS (reflected, context-aware), SSRF (internal IP + OOB callback). "
                        "Performs real exploit payloads to CONFIRM vulnerabilities. "
                        "Carries confidence=\"validated\" (FP rate <10%).",
            input_schema={
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL to scan (must be in scope)",
                    },
                    "modules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "default": ["sqli", "xss", "ssrf"],
                        "description": "Modules: sqli, xss, ssrf",
                    },
                    "oob_callback": {
                        "type": "string",
                        "default": "",
                        "description": "OOB callback URL for SSRF confirmation (optional, supports {id} placeholder)",
                    },
                    "timeout_sec": {
                        "type": "integer",
                        "default": 300,
                        "description": "Per-request timeout in seconds",
                    },
                    "rate_limit": {
                        "type": "integer",
                        "default": 60,
                        "description": "Requests per minute (anti-WAF)",
                    },
                },
                "required": ["target"],
            },
            handler=_handle_web_vuln_scan,
        ),
    ]
