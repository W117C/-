"""Unit tests for WAF/CDN detection."""
from __future__ import annotations

from secagent.core.waf_detect import detect_waf_from_raw


def test_cloudflare_detection():
    raw = {
        "headers": {
            "Server": "cloudflare",
            "CF-Ray": "abc123",
        },
        "webserver": "cloudflare",
    }
    result = detect_waf_from_raw(raw)
    assert any(d["name"] == "Cloudflare" for d in result)


def test_aws_cloudfront():
    raw = {
        "headers": {
            "X-Amz-Cf-Id": "xyz789",
            "X-Amz-Cf-Pop": "IAD50-C1",
        },
        "webserver": "",
    }
    result = detect_waf_from_raw(raw)
    names = [d["name"] for d in result]
    assert "AWS CloudFront" in names


def test_akamai():
    raw = {
        "headers": {
            "X-Akamai-Transformed": "yes",
        },
        "webserver": "",
    }
    result = detect_waf_from_raw(raw)
    assert any(d["name"] == "Akamai" for d in result)


def test_no_waf():
    raw = {
        "headers": {
            "Content-Type": "text/html",
            "Server": "nginx/1.24.0",
        },
        "webserver": "nginx/1.24.0",
    }
    result = detect_waf_from_raw(raw)
    assert len(result) == 0


def test_multiple_wafs():
    """Multiple WAF/CDN services can be detected."""
    raw = {
        "headers": {
            "Server": "cloudflare",
            "CF-Ray": "abc123",
            "X-Sucuri-Id": "test",
        },
        "webserver": "",
    }
    result = detect_waf_from_raw(raw)
    names = [d["name"] for d in result]
    assert "Cloudflare" in names
    assert "Sucuri CloudProxy" in names


def test_none_raw():
    assert detect_waf_from_raw(None) == []


def test_empty_raw():
    assert detect_waf_from_raw({}) == []


def test_dedup():
    """Same WAF name+type shouldn't appear twice, but different types count."""
    raw = {
        "headers": {
            "Server": "cloudflare",
            "CF-Ray": "abc",
            "CF-Cache-Status": "HIT",
        },
        "webserver": "cloudflare",
    }
    result = detect_waf_from_raw(raw)
    # Cloudflare appears as both "CDN + WAF" (server + cf-ray) and "CDN" (cf-cache-status)
    assert len(result) == 2
    assert any(d["name"] == "Cloudflare" and d["type"] == "CDN + WAF" for d in result)
    assert any(d["name"] == "Cloudflare" and d["type"] == "CDN" for d in result)
