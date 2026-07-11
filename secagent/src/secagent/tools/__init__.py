"""Tool function layer — each function wires an adapter through the compliance gate.

These functions are the boundary between "MCP/server layer" (M2b) and
"adapter layer" (M2a). The MCP server calls these; tests verify them
independently.
"""

__all__ = [
    "attack_surface_scan",
    "check_health",
    "crawl_target",
    "crawl_with_katana",
    "discover_paths",
    "enumerate_subdomains",
    "fingerprint_tls",
    "gather_osint",
    "passive_recon",
    "probe_services",
    "resolve_dns",
    "scan_ports",
    "scan_secret_leaks",
    "scan_vulnerabilities",
    "search_engines",
    "web_vuln_scan",
]
