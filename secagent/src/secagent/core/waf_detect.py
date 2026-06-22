"""WAF/CDN detection from HTTP response headers and server signatures.

Detects web application firewalls and CDN providers based on known
header patterns and server banners. Used by probe_services (httpx)
to annotate findings with WAF/CDN info.
"""
from __future__ import annotations

from typing import Any

# Known WAF/CDN signatures: (header_name, value_pattern, provider_name)
_WAF_SIGNATURES: list[tuple[str, str, str, str]] = [
    # Cloudflare
    ("server", "cloudflare", "Cloudflare", "CDN + WAF"),
    ("cf-ray", "", "Cloudflare", "CDN + WAF"),
    ("cf-cache-status", "", "Cloudflare", "CDN"),
    ("cf-request-id", "", "Cloudflare", "CDN + WAF"),
    # AWS CloudFront
    ("x-amz-cf-id", "", "AWS CloudFront", "CDN"),
    ("x-amz-cf-pop", "", "AWS CloudFront", "CDN"),
    ("x-amz-request-id", "", "AWS", "Cloud"),
    # AWS WAF / ALB
    ("x-amzn-trace-id", "", "AWS WAF/ALB", "WAF"),
    ("x-amzn-requestid", "", "AWS WAF/ALB", "WAF"),
    ("x-amzn-ErrorType", "", "AWS WAF/ALB", "WAF"),
    # Akamai
    ("x-akamai-", "", "Akamai", "CDN"),
    ("x-akamai-transformed", "", "Akamai", "CDN"),
    # Fastly
    ("x-fastly-", "", "Fastly", "CDN"),
    ("x-served-by", "cache-", "Fastly", "CDN"),
    ("x-cache-hits", "", "Fastly/CDN", "CDN"),
    # Imperva / Incapsula
    ("x-iinfo", "", "Imperva/Incapsula", "WAF"),
    ("x-cdn", "incapsula", "Imperva/Incapsula", "WAF"),
    ("x-visid", "", "Imperva/Incapsula", "WAF"),
    # Sucuri / CloudProxy
    ("x-sucuri-id", "", "Sucuri CloudProxy", "WAF"),
    ("x-sucuri-cache", "", "Sucuri CloudProxy", "CDN"),
    # ModSecurity / OWASP CRS
    ("x-owasp-modsecurity", "", "ModSecurity (OWASP CRS)", "WAF"),
    # F5 BIG-IP ASM
    ("x-application-context", "", "F5 BIG-IP ASM", "WAF"),
    ("x-wa-", "", "F5 BIG-IP ASM", "WAF"),
    # Citrix Netscaler
    ("ns_client", "", "Citrix Netscaler", "ADC"),
    # Barracuda
    ("x-barracuda-", "", "Barracuda WAF", "WAF"),
    # Fortinet FortiWeb
    ("x-fortiweb", "", "Fortinet FortiWeb", "WAF"),
    # radware
    ("x-radware-", "", "Radware WAF", "WAF"),
    # StackPath
    ("x-stackpath-", "", "StackPath", "CDN"),
    # KeyCDN
    ("x-keycdn-", "", "KeyCDN", "CDN"),
    # BunnyCDN
    ("x-bunny-", "", "BunnyCDN", "CDN"),
    # Generic CDN
    ("via", "cdn", "Generic CDN", "CDN"),
    ("x-cdn", "", "Generic CDN", "CDN"),
    # Varnish (often used as CDN cache)
    ("x-varnish", "", "Varnish Cache", "Cache"),
    # Nginx + ModSecurity
    ("server", "nginx", None, None),  # tracked separately
]

# Known CDN IP ranges (DNS-based detection)
_CDN_NS_PATTERNS: list[tuple[str, str, str]] = [
    ("cloudflare", "Cloudflare", "CDN + WAF"),
    ("akamai", "Akamai", "CDN"),
    ("fastly", "Fastly", "CDN"),
    ("cloudfront", "AWS CloudFront", "CDN"),
]


def detect_waf_from_raw(raw: dict[str, Any] | None) -> list[dict[str, str]]:
    """Detect WAF/CDN from raw httpx JSON output.

    Args:
        raw: The raw JSON object from httpx, which includes
             'headers' (dict), 'webserver' (str), etc.

    Returns:
        List of {name, type} dicts for each detected WAF/CDN.
    """
    if not raw or not isinstance(raw, dict):
        return []

    detected: list[dict[str, str]] = []
    headers = raw.get("headers", {}) or {}
    webserver = str(raw.get("webserver", "") or "").lower()

    if not isinstance(headers, dict):
        return detected

    # Check headers
    for hdr, val_pattern, name, waf_type in _WAF_SIGNATURES:
        if not name:  # skip markers
            continue
        # Check if header exists
        hdr_lower = hdr.lower()
        for actual_hdr in headers:
            if hdr_lower in actual_hdr.lower():
                hdr_val = str(headers[actual_hdr])
                if not val_pattern or val_pattern.lower() in hdr_val.lower():
                    detected.append({"name": name, "type": waf_type})
                    break

    # Check webserver field
    server_wafs = [
        ("cloudflare", "Cloudflare", "CDN + WAF"),
        ("akamai", "Akamai", "CDN"),
        ("sucuri", "Sucuri CloudProxy", "WAF"),
    ]
    for sig, name, waf_type in server_wafs:
        if sig in webserver and not any(d["name"] == name for d in detected):
            detected.append({"name": name, "type": waf_type})

    # Deduplicate
    seen: set[tuple[str, str]] = set()
    deduped = []
    for d in detected:
        key = (d["name"], d["type"])
        if key not in seen:
            seen.add(key)
            deduped.append(d)

    return deduped
