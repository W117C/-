"""JavaScript 反混淆与敏感信息提取器 — Web 逆向核心模块。

支持 JS 美化/去混淆、敏感信息提取（API Key/端点/IP/域名）、
常见混淆模式检测（eval/atob/自执行函数/字符串拼接/数组映射）。
"""
from __future__ import annotations

import re
from typing import Any


# ==========================================================================
# JS 美化与反混淆
# ==========================================================================

def beautify(js_code: str, indent: int = 2) -> str:
    """简单的 JS 代码格式化（缩进、换行）。

    不依赖外部库，适合快速查看混淆代码结构。
    高级美化建议使用 jsbeautifier 库。

    Args:
        js_code: 原始 JavaScript 代码。
        indent: 缩进空格数。

    Returns:
        格式化后的代码。
    """
    lines = []
    current_indent = 0

    i = 0
    indent_str = " " * indent
    while i < len(js_code):
        ch = js_code[i]
        if ch in "}])":
            current_indent = max(0, current_indent - 1)
            lines.append(indent_str * current_indent)
            lines.append(ch)
            if i + 1 < len(js_code) and js_code[i + 1] not in ",;)]}":
                lines.append("\n")
        elif ch in "{[":
            lines.append(ch)
            lines.append("\n")
            current_indent += 1
        elif ch == ";":
            lines.append(ch)
            lines.append("\n")
        elif ch == ",":
            lines.append(ch)
            if current_indent > 0:
                lines.append("\n")
                lines.append(indent_str * current_indent)
            else:
                lines.append(" ")
        elif ch == "\n":
            lines.append(ch)
            if current_indent > 0:
                lines.append(indent_str * current_indent)
        elif ch == " " and (i + 1 < len(js_code) and js_code[i + 1] == " "):
            pass  # 折叠连续空格
        else:
            lines.append(ch)
        i += 1

    return "".join(lines)


# ==========================================================================
# 混淆模式检测
# ==========================================================================

_ObfuscationPattern = tuple[str, str, str]

_OBFUSCATION_PATTERNS: list[_ObfuscationPattern] = [
    ("eval", "全局 eval 执行", r"\beval\s*\(.*?\)"),
    ("Function", "Function 构造器", r"new\s+Function\s*\(.*?\)"),
    ("atob", "Base64 解码执行", r"\batob\s*\(\s*['\"][A-Za-z0-9+/=]{20,}"),
    ("atob_chain", "Base64 链式解码", r"atob\s*\(\s*atob\s*\("),
    ("hex_escape", "十六进制转义字符串", r"\\x[0-9a-fA-F]{2}"),
    ("unicode_escape", "Unicode 转义字符串", r"\\u[0-9a-fA-F]{4}"),
    ("string_concat", "字符串拼接混淆", r"['\"][^'\"]*['\"]\s*\+\s*['\"][^'\"]*['\"]"),
    ("array_mapping", "数组字符串映射", r"var\s+\w+\s*=\s*\[['\"].*?['\"]"),
    ("char_code", "String.fromCharCode", r"String\.fromCharCode\s*\("),
    ("number_base", "数字进制混淆", r"0[xXoObB][0-9a-fA-F]+"),
    ("self_executing", "自执行函数", r"\(function\s*\(.*?\)\s*\{"),
    ("packed", "Packer 混淆", r"}\s*\(\s*['\"]\w+['\"],\s*\d+,\s*\d+,\s*['\"]"),
    ("sojson", "Sojson 混淆", r"\b_\d{3,}\s*=|\bwindow\s*\[\s*['\"][\w$]{4,}['\"]"),
    ("obfuscator_io", "javascript-obfuscator", r"var\s+_\w{3,}\s*=\s*\[['\"].*?['\"]\]"),
]


def detect_obfuscation(js_code: str) -> list[dict[str, Any]]:
    """检测 JS 代码中的混淆模式。

    Args:
        js_code: JavaScript 源代码。

    Returns:
        检测到的混淆模式列表，每项包含 name/description/match_count/confidence。
    """
    results: list[dict[str, Any]] = []

    for name, desc, pattern in _OBFUSCATION_PATTERNS:
        matches = re.findall(pattern, js_code, re.I)
        if matches:
            confidence = min(len(matches) * 10, 95)
            if name in ("string_concat", "number_base") and len(matches) > 10:
                confidence = min(90, confidence + 20)
            results.append({
                "name": name,
                "description": desc,
                "match_count": len(matches),
                "confidence": confidence,
            })

    results.sort(key=lambda r: r["confidence"], reverse=True)
    return results


# ==========================================================================
# 敏感信息提取
# ==========================================================================

_SENSITIVE_PATTERNS: list[tuple[str, str, str]] = [
    ("aws_key", "AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("aws_secret", "AWS Secret Key", r"(?i)aws[_-]?secret(?:[=:'\" ]+)([A-Za-z0-9+/]{40})"),
    ("google_api", "Google API Key", r"AIza[0-9A-Za-z\-_]{35}"),
    ("github_token", "GitHub Token", r"gh[pousr]_[A-Za-z0-9_]{36,}"),
    ("slack_token", "Slack Token", r"xox[baprs]-[0-9a-z-]{10,}"),
    ("jwt_token", "JWT Token", r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("bearer_token", "Bearer Token", r"(?i)bearer\s+[A-Za-z0-9\-_.]{16,}"),
    ("basic_auth", "Basic Auth", r"(?i)basic\s+[A-Za-z0-9+/=]{8,}"),
    ("private_key", "Private Key Block", r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----"),
    ("token_var", "Token Variable", r"(?i)(?:api[_-]?key|token|secret|password)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]"),
    ("api_endpoint", "API Endpoint", r"['\"](?:http[s]?://[^'\"]*?/api/[^'\"]*)['\"]"),
    ("internal_host", "Internal Hostname", r"['\"](?:http://)?(?:localhost|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.1[6-9]\.\d{1,3}\.\d{1,3}|172\.2[0-9]\.\d{1,3}\.\d{1,3}|172\.3[0-1]\.\d{1,3}\.\d{1,3})['\"]"),
    ("ipv4", "IPv4 Address", r"['\"]?\b(?:\d{1,3}\.){3}\d{1,3}\b['\"]?"),
    ("email", "Email Address", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    ("password", "Password String", r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,})['\"]"),
    ("conn_string", "DB Connection String", r"(?i)(?:mysql|postgres|mongodb)\://[^\s'\"}]+\@[^\s'\"}]+"),
    ("debug_endpoint", "Debug Endpoint", r"['\"](?:/debug|/actuator|/swagger|/api-docs)[^'\"]*['\"]"),
    ("s3_bucket", "S3 Bucket", r"(?i)s3://[a-z0-9.-]+"),
    ("webhook_url", "Webhook URL", r"(?i)(?:webhook|callback|notify)_?url\s*[=:]\s*['\"](https?://[^'\"]+)['\"]"),
]


def extract_sensitive(js_code: str) -> list[dict[str, Any]]:
    """从 JS 代码中提取敏感信息。

    Args:
        js_code: JavaScript 源代码。

    Returns:
        找到的敏感信息列表，每项包含 type/description/value/line。
    """
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()

    for stype, desc, pattern in _SENSITIVE_PATTERNS:
        for match in re.finditer(pattern, js_code, re.I):
            value = match.group(0).strip()
            if len(value) > 500 or len(value) < 3:
                continue
            key = f"{stype}:{value[:50]}"
            if key in seen:
                continue
            seen.add(key)
            line_approx = js_code[:match.start()].count("\n") + 1
            findings.append({
                "type": stype,
                "description": desc,
                "value": value[:200],
                "line": line_approx,
            })

    findings.sort(key=lambda f: f["type"])
    return findings


# ==========================================================================
# 编码字符串提取与解码
# ==========================================================================

def extract_encoded_strings(js_code: str) -> list[dict[str, Any]]:
    """提取并尝试解码 JS 中编码的字符串。

    检测 Base64、MD5/SHA 等编码的字符串常量。

    Args:
        js_code: JavaScript 源代码。

    Returns:
        解码后的字符串列表。
    """
    results: list[dict[str, Any]] = []
    seen: set[str] = set()

    string_patterns = [
        r"['\"]([A-Za-z0-9+/]{20,}={0,2})['\"]",
        r"['\"]([0-9a-fA-F]{32,})['\"]",
    ]

    from secagent.core.decoders import auto_decode

    for pattern in string_patterns:
        for match in re.finditer(pattern, js_code):
            raw = match.group(1)
            if raw in seen:
                continue
            seen.add(raw)
            decoded_layers = auto_decode(raw, max_depth=2)
            if decoded_layers:
                results.append({
                    "original": raw[:80],
                    "decoded_layers": decoded_layers,
                    "final": decoded_layers[-1]["result"][:200],
                })

    return results


# ==========================================================================
# 常见混淆的还原辅助
# ==========================================================================

def try_decrypt_sojson(js_code: str) -> str | None:
    """尝试还原 Sojson 混淆。

    特征：大量 \\uXXXX 编码 + eval + 窗口对象引用。

    Args:
        js_code: Sojson 混淆的代码。

    Returns:
        还原后的代码片段，或 None。
    """
    from secagent.core.decoders import try_decode, EncodingType

    decoded = try_decode(js_code, EncodingType.UNICODE_ESCAPE)
    if decoded and decoded != js_code:
        return decoded
    return None


def decode_hex_strings(js_code: str) -> dict[str, str]:
    """解码 JS 中的 xXX 十六进制转义字符串。

    Returns:
        {原始字符串: 解码后字符串} 的映射。
    """
    from secagent.core.decoders import try_decode, EncodingType
    results: dict[str, str] = {}
    for match in re.finditer(r"'((?:\\x[0-9a-fA-F]{2})+)\\'", js_code):
        raw = match.group(1)
        decoded = try_decode(raw, EncodingType.HEX)
        if decoded:
            results[raw[:50]] = decoded
    return results
