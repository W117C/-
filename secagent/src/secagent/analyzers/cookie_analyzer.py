"""Cookie/Token/JWT 分析器 — Web 逆向核心工具。

分析身份认证令牌的结构、编码、字段含义，支持 JWT 解码、
Cookie 属性分析、Token 模式识别和常见编码自动检测。
"""
from __future__ import annotations

import base64
import json
import math
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any


# ==========================================================================
# Token 类型检测
# ==========================================================================

_TOKEN_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("jwt", "JWT (JSON Web Token)", re.compile(r"^eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}$")),
    ("jwt_short", "JWT (compact)", re.compile(r"^eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}$")),
    ("base64_token", "Base64 Token", re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")),
    ("base64url_token", "Base64URL Token", re.compile(r"^[A-Za-z0-9_-]{20,}$")),
    ("hex_token", "Hex Token", re.compile(r"^[0-9a-fA-F]{32,}$")),
    ("uuid", "UUID", re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)),
    ("numeric_id", "Numeric ID", re.compile(r"^\d{8,}$")),
    ("session_id", "Session ID", re.compile(r"^[A-Za-z0-9]{16,64}$")),
]


def detect_token_type(token: str) -> list[dict[str, Any]]:
    """检测 Token 的类型和编码。"""
    results: list[dict[str, Any]] = []
    for name, desc, pattern in _TOKEN_PATTERNS:
        if pattern.match(token.strip()):
            confidence = 90 if name == "jwt" else 70
            results.append({"type": name, "description": desc, "confidence": confidence})
    return results


# ==========================================================================
# JWT 分析
# ==========================================================================

@dataclass
class JWTResult:
    raw: str = ""
    header: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    signature: str = ""
    valid_structure: bool = False
    algorithm: str = ""
    issuer: str = ""
    subject: str = ""
    issued_at: str = ""
    expires_at: str = ""
    remaining_seconds: float = 0.0
    payload_claims: dict[str, Any] = field(default_factory=dict)


def analyze_jwt(token: str) -> JWTResult:
    """全量分析 JWT Token。"""
    result = JWTResult(raw=token)
    parts = token.strip().split(".")
    if len(parts) != 3:
        return result

    result.valid_structure = True
    result.signature = parts[2]

    try:
        padded = parts[0] + "=" * (4 - len(parts[0]) % 4)
        result.header = json.loads(base64.urlsafe_b64decode(padded))
        result.algorithm = result.header.get("alg", "")
    except Exception:
        pass

    try:
        padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
        result.payload = json.loads(base64.urlsafe_b64decode(padded))
        result.payload_claims = dict(result.payload)
    except Exception:
        return result

    now = time.time()
    result.issuer = str(result.payload.get("iss", ""))
    result.subject = str(result.payload.get("sub", ""))

    if "iat" in result.payload:
        result.issued_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.payload["iat"]))
    if "exp" in result.payload:
        result.expires_at = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(result.payload["exp"]))
        result.remaining_seconds = max(0, result.payload["exp"] - now)

    return result


def analyze_jwt_claims(payload: dict[str, Any]) -> dict[str, Any]:
    """解读 JWT Payload 中的自定义声明。"""
    standard_keys = {"iss", "sub", "aud", "exp", "nbf", "iat", "jti", "typ"}
    permission_keys = {"roles", "role", "permissions", "permission", "scope", "scopes", "groups", "group", "privileges", "access"}

    standard, user, permissions, other = {}, {}, [], {}
    for key, value in payload.items():
        if key.lower() in standard_keys:
            standard[key] = value
        elif key.lower() in permission_keys:
            permissions.extend(value) if isinstance(value, list) else permissions.append(str(value))
        elif any(kw in key.lower() for kw in ("id", "name", "email")):
            user[key] = value
        else:
            other[key] = value

    return {"standard_claims": standard, "user_claims": user, "permissions": permissions, "other_claims": other}


# ==========================================================================
# Cookie 分析
# ==========================================================================

@dataclass
class CookieInfo:
    name: str = ""
    value: str = ""
    domain: str = ""
    path: str = "/"
    secure: bool = False
    httponly: bool = False
    samesite: str = ""
    expires: str = ""
    max_age: int = 0
    size: int = 0
    is_session: bool = False
    is_auth: bool = False
    is_encrypted: bool = False
    token_type: list[dict[str, Any]] = field(default_factory=list)
    decoded_value: str = ""


def analyze_cookie(name: str, value: str) -> CookieInfo:
    """分析一个 Cookie 的名称和值。"""
    result = CookieInfo(name=name, value=value, size=len(value))

    name_lower = name.lower()
    if any(kw in name_lower for kw in ("session", "sid", "phpsessid", "jsessionid", "aspsessionid", "connect.sid")):
        result.is_session = True
    if any(kw in name_lower for kw in ("token", "auth", "jwt", "login", "identity", "credential", "access")):
        result.is_auth = True

    result.token_type = detect_token_type(value)
    if result.token_type:
        from secagent.core.decoders import auto_decode
        decoded_layers = auto_decode(value, max_depth=2)
        if decoded_layers:
            result.decoded_value = decoded_layers[-1]["result"][:200]
            result.is_encrypted = True

    if not result.token_type and re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", value):
        result.is_encrypted = True
        from secagent.core.decoders import try_decode
        decoded = try_decode(value, "base64")
        if decoded:
            result.decoded_value = decoded[:200]

    return result


def analyze_cookies(cookies: dict[str, str] | list[tuple[str, str]]) -> list[CookieInfo]:
    """批量分析多个 Cookie。"""
    items = list(cookies.items()) if isinstance(cookies, dict) else list(cookies)
    results = [analyze_cookie(n, v) for n, v in items]
    results.sort(key=lambda c: (not c.is_auth, not c.is_session, c.name))
    return results


# ==========================================================================
# Token 安全性评估
# ==========================================================================

def assess_token_security(token: str) -> dict[str, Any]:
    """评估一个 Token 的安全性。"""
    result: dict[str, Any] = {
        "length": len(token),
        "entropy": _estimate_entropy(token),
        "issues": [],
        "recommendations": [],
    }

    if token.startswith("eyJ"):
        jwt_result = analyze_jwt(token)
        result["type"] = "JWT"
        result["algorithm"] = jwt_result.algorithm

        if jwt_result.algorithm == "none":
            result["issues"].append("Algorithm is 'none' -- no signature verification")
        elif jwt_result.algorithm == "HS256":
            result["issues"].append("Uses symmetric key (HS256) -- verify secret strength")

        if jwt_result.payload:
            result["payload"] = jwt_result.payload_claims
            readable = any(isinstance(v, str) and len(v) > 3 for v in jwt_result.payload.values())
            if readable:
                result["issues"].append("Payload contains human-readable data")

            if jwt_result.remaining_seconds > 0:
                result["expires_in"] = f"{jwt_result.remaining_seconds:.0f}s"
                if jwt_result.remaining_seconds > 86400 * 30:
                    result["issues"].append(f"Token expires in >30 days ({jwt_result.remaining_seconds / 86400:.0f}d)")
            else:
                result["issues"].append("Token has expired")
    else:
        result["type"] = "generic"
        if re.match(r"^[A-Za-z0-9+/]{20,}={0,2}$", token):
            result["issues"].append("Appears to be Base64 -- decode and inspect")
        if token.isdigit() and len(token) < 12:
            result["issues"].append("Numeric token -- predictable")

    if len(token) < 20:
        result["issues"].append(f"Short token ({len(token)} chars) -- may be guessable")
    if not result["issues"]:
        result["recommendations"].append("Token appears reasonably secure")

    return result


def _estimate_entropy(token: str) -> float:
    """估算字符串的香农熵。"""
    if not token:
        return 0.0
    freq = Counter(token)
    length = len(token)
    entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
    return round(entropy, 2)
