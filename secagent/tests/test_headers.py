"""Tests for core/headers.py — UA, headers, fingerprint, URL params."""
from __future__ import annotations

from secagent.core.headers import (
    analyze_url_params,
    build_headers,
    fingerprint_headers,
    parse_ua,
    random_ua,
)


# ==========================================================================
# random_ua
# ==========================================================================

def test_random_ua_chrome_mac():
    ua = random_ua("chrome_mac")
    assert ua.startswith("Mozilla/5.0")
    assert "Chrome/" in ua
    assert "Mac OS X" in ua


def test_random_ua_firefox():
    ua = random_ua("firefox_mac")
    assert "Firefox/" in ua
    assert "Gecko" in ua


def test_random_ua_safari():
    ua = random_ua("safari")
    assert "Safari/" in ua
    assert "Chrome" not in ua  # real Safari UA doesn't say Chrome


def test_random_ua_mobile():
    ua = random_ua("mobile")
    assert "Mobile" in ua or "Android" in ua or "iPhone" in ua


def test_random_ua_bot():
    ua = random_ua("bot")
    assert "bot" in ua.lower() or "Bot" in ua


def test_random_ua_none_category():
    """No category = random from all pools."""
    ua = random_ua()
    assert ua.startswith("Mozilla/")


# ==========================================================================
# parse_ua
# ==========================================================================

def test_parse_ua_chrome_mac():
    ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    r = parse_ua(ua)
    assert r["browser"] == "Chrome"
    assert r["os"] == "macOS"
    assert r["device"] == "desktop"


def test_parse_ua_firefox():
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
    r = parse_ua(ua)
    assert r["browser"] == "Firefox"
    assert r["os"] == "Windows"


def test_parse_ua_mobile():
    ua = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1"
    r = parse_ua(ua)
    assert r["browser"] == "Safari"
    assert r["os"] == "iOS"
    assert r["device"] == "mobile"


def test_parse_ua_bot():
    ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    r = parse_ua(ua)
    assert r["browser"] == "bot"
    assert r["device"] == "bot"


def test_parse_ua_unknown():
    r = parse_ua("SomeJunk/1.0")
    assert r["browser"] == "unknown"


# ==========================================================================
# build_headers
# ==========================================================================

def test_build_headers_default():
    h = build_headers()
    assert "User-Agent" in h
    assert "Sec-Ch-Ua" in h
    assert "Accept" in h


def test_build_headers_accept_json():
    h = build_headers(accept_json=True)
    assert "application/json" in h.get("Accept", "")


def test_build_headers_custom_ua():
    h = build_headers(ua="CustomUA/1.0")
    assert h["User-Agent"] == "CustomUA/1.0"


def test_build_headers_origin_referer():
    h = build_headers(origin="https://example.com", referer="https://example.com/page")
    assert h["Origin"] == "https://example.com"
    assert h["Referer"] == "https://example.com/page"


def test_build_headers_extra():
    h = build_headers(extra={"X-Custom": "value"})
    assert h["X-Custom"] == "value"


# ==========================================================================
# fingerprint_headers
# ==========================================================================

def test_fingerprint_cloudflare():
    r = fingerprint_headers({"Server": "cloudflare", "CF-Ray": "abc"})
    assert any(d["name"] == "Cloudflare" for d in r)


def test_fingerprint_cloudfront():
    r = fingerprint_headers({"X-Amz-Cf-Id": "abc", "X-Amz-Cf-Pop": "IAD50"})
    assert any(d["name"] == "AWS CloudFront" for d in r)


def test_fingerprint_akamai():
    r = fingerprint_headers({"X-Akamai-Transformed": "abc"})
    assert any(d["name"] == "Akamai" for d in r)


def test_fingerprint_fastly():
    r = fingerprint_headers({"X-Served-By": "cache-sjc1000001"})
    assert any(d["name"] == "Fastly" for d in r)


def test_fingerprint_imperva():
    r = fingerprint_headers({"X-Iinfo": "abc123"})
    assert any(d["name"] == "Imperva/Incapsula" for d in r)


def test_fingerprint_multiple():
    """Multiple WAFs detected simultaneously."""
    r = fingerprint_headers({"Server": "cloudflare", "X-Amz-Cf-Id": "abc"})
    names = {d["name"] for d in r}
    assert "Cloudflare" in names
    assert "AWS CloudFront" in names


def test_fingerprint_no_waf():
    """Ordinary headers should not trigger any WAF detection."""
    r = fingerprint_headers({"Server": "nginx", "Content-Type": "text/html"})
    assert len(r) == 0


def test_fingerprint_empty():
    assert fingerprint_headers({}) == []


# ==========================================================================
# analyze_url_params
# ==========================================================================

def test_analyze_url_params_basic():
    r = analyze_url_params("https://example.com/api?id=123&name=admin")
    assert r["hostname"] == "example.com"
    assert r["path"] == "/api"
    assert len(r["params"]) == 2


def test_analyze_url_params_detects_md5():
    r = analyze_url_params("https://x.com/data?sign=e10adc3949ba59abbe56e057f20f883e")
    assert any("sign" in s for s in r["signals"])


def test_analyze_url_params_detects_timestamp():
    r = analyze_url_params("https://x.com/data?ts=1712345678")
    assert any("timestamp" in s for s in r["signals"])


def test_analyze_url_params_detects_base64():
    r = analyze_url_params("https://x.com/data?token=SGVsbG9Xb3JsZEFCQ0RFRkdISUo=")
    assert any("base64" in str(p).lower() for p in r["params"].values())


def test_analyze_url_params_security_signals():
    """Parameters like sign/sig/token/ts should generate security signals."""
    r = analyze_url_params("https://x.com/api?sign=abc&token=def&ts=1712345678")
    assert len(r["signals"]) >= 2
