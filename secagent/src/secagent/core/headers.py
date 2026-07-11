"""HTTP 头部分析与请求伪造工具集 — Web 逆向核心模块。

提供 HTTP 头部的指纹识别、自定义指纹生成、请求参数分析、
User-Agent 轮换等功能，用于绕过 WAF/CDN 和伪造请求。
"""
from __future__ import annotations

import random
import re
from dataclasses import dataclass
from typing import Any

# ---------------------------------------------------------------------------
# User-Agent 池
# ---------------------------------------------------------------------------

_UA_POOL: dict[str, list[str]] = {
    "chrome_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    ],
    "chrome_win": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    ],
    "chrome_linux": [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    ],
    "firefox_mac": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:127.0) Gecko/20100101 Firefox/127.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0",
    ],
    "safari": [
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    ],
    "mobile": [
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
    ],
    "bot": [
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; Bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "Twitterbot/1.0",
    ],
}

# 常用浏览器指纹字段
_BROWSER_FINGERPRINT_FIELDS = {
    "chrome": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Google Chrome";v="125", "Chromium";v="125", "Not.A/Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"macOS"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
        "Connection": "keep-alive",
    },
    "firefox": {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3",
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    },
}


# ---------------------------------------------------------------------------
# User-Agent 工具
# ---------------------------------------------------------------------------

def random_ua(category: str | None = None) -> str:
    """获取随机 User-Agent。

    Args:
        category: 设备/浏览器类别。
                  None 表示所有浏览器类别中随机（不含 bot 类别）；
                  可选: chrome_mac, chrome_win, firefox_mac, safari, mobile, bot

    Returns:
        User-Agent 字符串。
    """
    if category and category in _UA_POOL:
        return random.choice(_UA_POOL[category])
    # General random: exclude bot pool (different format, used for crawler detection)
    browser_pools = [uas for cat, uas in _UA_POOL.items() if cat != "bot"]
    all_uas = [ua for uas in browser_pools for ua in uas]
    return random.choice(all_uas)


def parse_ua(ua: str) -> dict[str, Any]:
    """解析 User-Agent 提取设备/浏览器/OS 信息。

    Args:
        ua: User-Agent 字符串。

    Returns:
        {"browser": ..., "os": ..., "device": ..., "version": ...}。
    """
    result: dict[str, Any] = {"browser": "unknown", "os": "unknown",
                              "device": "desktop", "version": "unknown"}

    # 浏览器检测
    if "Chrome/" in ua and "Chromium" not in ua:
        result["browser"] = "Chrome"
        m = re.search(r"Chrome/([\d.]+)", ua)
        if m:
            result["version"] = m.group(1)
    elif "Firefox/" in ua:
        result["browser"] = "Firefox"
        m = re.search(r"Firefox/([\d.]+)", ua)
        if m:
            result["version"] = m.group(1)
    elif "Safari/" in ua and "Chrome" not in ua:
        result["browser"] = "Safari"
        m = re.search(r"Version/([\d.]+)", ua)
        if m:
            result["version"] = m.group(1)
    elif "bot" in ua.lower() or "crawler" in ua.lower() or "spider" in ua.lower():
        result["browser"] = "bot"
        result["device"] = "bot"

    # OS 检测
    if "iPhone" in ua or "iPad" in ua or "iPod" in ua:
        result["os"] = "iOS"
        result["device"] = "mobile"
    elif "Android" in ua:
        result["os"] = "Android"
        result["device"] = "mobile"
    elif "Mac OS X" in ua:
        result["os"] = "macOS"
    elif "Windows NT" in ua:
        result["os"] = "Windows"
    elif "Linux" in ua and "Android" not in ua:
        result["os"] = "Linux"

    return result


# ---------------------------------------------------------------------------
# 浏览器指纹生成
# ---------------------------------------------------------------------------

def build_headers(
    browser: str = "chrome",
    ua: str | None = None,
    origin: str | None = None,
    referer: str | None = None,
    accept_json: bool = False,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """构建模拟浏览器请求头。

    自动填充 Sec-Fetch-*、Accept、Accept-Language 等浏览器默认字段。

    Args:
        browser: "chrome" 或 "firefox"。
        ua: 自定义 UA（None 则自动生成）。
        origin: Origin 头部（跨域请求时使用）。
        referer: Referer 头部。
        accept_json: 是否请求 JSON（Accept: application/json）。
        extra: 额外自定义头部。

    Returns:
        完整的请求头 dict。
    """
    template = dict(_BROWSER_FINGERPRINT_FIELDS.get(browser,
                    _BROWSER_FINGERPRINT_FIELDS["chrome"]))

    if ua:
        template["User-Agent"] = ua
    else:
        template["User-Agent"] = random_ua(f"{browser}_mac")

    if origin:
        template["Origin"] = origin
    if referer:
        template["Referer"] = referer
    if accept_json:
        template["Accept"] = "application/json, text/plain, */*"

    # 更新 Sec-Ch-Ua-Platform 以匹配 UA
    ua_info = parse_ua(template["User-Agent"])
    if ua_info["os"] == "Windows":
        template["Sec-Ch-Ua-Platform"] = '"Windows"'
    elif ua_info["os"] == "Linux":
        template["Sec-Ch-Ua-Platform"] = '"Linux"'

    if extra:
        template.update(extra)

    return template


# ---------------------------------------------------------------------------
# HTTP 头部指纹检测
# ---------------------------------------------------------------------------

# WAF/CDN 指纹库：头名称 -> 值模式 -> (提供商, 类型)
_WAF_SIGNATURES: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"cloudflare", re.I), "Cloudflare", "CDN + WAF"),
    (re.compile(r"^cf-", re.I), "Cloudflare", "CDN + WAF"),
    (re.compile(r"x-amz-cf-", re.I), "AWS CloudFront", "CDN"),
    (re.compile(r"x-amzn-", re.I), "AWS WAF/ALB", "WAF"),
    (re.compile(r"x-akamai-", re.I), "Akamai", "CDN"),
    (re.compile(r"x-fastly-", re.I), "Fastly", "CDN"),
    (re.compile(r"x-served-by", re.I), "Fastly", "CDN"),
    (re.compile(r"x-iinfo", re.I), "Imperva/Incapsula", "WAF"),
    (re.compile(r"x-sucuri-", re.I), "Sucuri CloudProxy", "WAF"),
    (re.compile(r"x-owasp-modsecurity", re.I), "ModSecurity (OWASP CRS)", "WAF"),
    (re.compile(r"x-wa-", re.I), "F5 BIG-IP ASM", "WAF"),
    (re.compile(r"ns_client", re.I), "Citrix Netscaler", "ADC"),
    (re.compile(r"x-barracuda-", re.I), "Barracuda WAF", "WAF"),
    (re.compile(r"x-fortiweb", re.I), "Fortinet FortiWeb", "WAF"),
    (re.compile(r"x-radware-", re.I), "Radware WAF", "WAF"),
    (re.compile(r"x-bunny-", re.I), "BunnyCDN", "CDN"),
    (re.compile(r"x-keycdn-", re.I), "KeyCDN", "CDN"),
    (re.compile(r"x-stackpath-", re.I), "StackPath", "CDN"),
    (re.compile(r"^x-varnish", re.I), "Varnish Cache", "Cache"),
]


def fingerprint_headers(headers: dict[str, str]) -> list[dict[str, str]]:
    """检测响应头中的 WAF/CDN 指纹。

    同时检查头部名称和值中的特征字符串。

    Args:
        headers: 原始 HTTP 响应头 dict。

    Returns:
        检测到的 [(名称, 类型), ...] 列表。
    """
    detected: list[dict[str, str]] = []
    seen: set[str] = set()

    for hdr_name, hdr_value in headers.items():
        hdr_lower = hdr_name.lower()
        hdr_val_lower = hdr_value.lower()

        for pattern, name, waf_type in _WAF_SIGNATURES:
            if name in seen:
                continue
            if pattern.search(hdr_lower) or pattern.search(hdr_val_lower):
                detected.append({"name": name, "type": waf_type})
                seen.add(name)

    # Server 头部特殊检测
    server = headers.get("Server", headers.get("server", "")).lower()
    server_map = {
        "cloudflare": ("Cloudflare", "CDN + WAF"),
        "akamai": ("Akamai", "CDN"),
        "sucuri": ("Sucuri CloudProxy", "WAF"),
    }
    for sig, (name, waf_type) in server_map.items():
        if sig in server and name not in seen:
            detected.append({"name": name, "type": waf_type})
            seen.add(name)

    return detected


# ---------------------------------------------------------------------------
# 请求参数分析
# ---------------------------------------------------------------------------

@dataclass
class RequestParam:
    """一个 HTTP 请求参数的解析结果。"""
    name: str
    value: str
    encoded: bool = False
    encoding_type: str | None = None
    looks_random: bool = False
    is_timestamp: bool = False
    is_hash: bool = False


def analyze_url_params(url: str) -> dict[str, Any]:
    """分析 URL 中的查询参数，检测常见的安全/逆向特征。

    Args:
        url: 完整 URL。

    Returns:
        包含参数分析和可疑信号的 dict。
    """
    from urllib.parse import parse_qs, urlparse

    parsed = urlparse(url)
    raw_params = parse_qs(parsed.query, keep_blank_values=True)

    params: dict[str, RequestParam] = {}
    signals: list[str] = []

    for name, values in raw_params.items():
        val = values[0] if values else ""
        p = RequestParam(name=name, value=val)

        # 编码检测
        from secagent.core.decoders import detect_encoding
        encodings = detect_encoding(val)
        if encodings:
            p.encoded = True
            p.encoding_type = encodings[0]

        # 随机值检测（32/40/64位 hex 或 base64-like）
        if re.match(r"^[a-f0-9]{32}$", val, re.I):
            p.looks_random = True
            p.is_hash = True
            signals.append(f"param '{name}' looks like MD5 hash")
        elif re.match(r"^[a-f0-9]{40}$", val, re.I):
            p.looks_random = True
            p.is_hash = True
            signals.append(f"param '{name}' looks like SHA1 hash")
        elif re.match(r"^[a-f0-9]{64}$", val, re.I):
            p.looks_random = True
            p.is_hash = True
            signals.append(f"param '{name}' looks like SHA256 hash")
        elif re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", val):
            p.looks_random = True
            signals.append(f"param '{name}' looks like Base64 token")

        # 时间戳检测
        if val.isdigit() and len(val) >= 10:
            from secagent.core.decoders import analyze_timestamp
            ts_info = analyze_timestamp(val)
            if "error" not in ts_info:
                p.is_timestamp = True
                signals.append(
                    f"param '{name}' = timestamp ({ts_info.get('utc_readable', '?')})"
                )

        params[name] = p

    # 签名/安全相关参数名检测
    sig_params = {"sign", "sig", "signature", "token", "_token",
                  "csrf", "csrf_token", "authenticity_token",
                  "nonce", "salt", "hmac", "secret", "key",
                  "api_key", "apikey", "appkey", "app_key",
                  "ts", "timestamp", "_t", "_time",
                  "callback", "jsonp", "format"}
    for name in params:
        if name.lower() in sig_params:
            signals.append(f"potential security parameter: '{name}'")

    return {
        "url": url,
        "scheme": parsed.scheme,
        "hostname": parsed.hostname,
        "path": parsed.path,
        "params": {k: {
            "name": v.name,
            "value": v.value,
            "encoded": v.encoded,
            "encoding": v.encoding_type,
            "random_looking": v.looks_random,
            "is_timestamp": v.is_timestamp,
            "is_hash": v.is_hash,
        } for k, v in params.items()},
        "signals": signals,
    }
