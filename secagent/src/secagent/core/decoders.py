"""编码解码工具集 — Web逆向中常用编码的智能检测和转换。

提供一套统一的 API 用于检测和转换常见数据编码格式，是 Web 逆向
分析的基础工具模块。支持链式调用和批量处理。
"""
from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import html
import json
import quopri
import re
import urllib.parse
from typing import Any


# ---------------------------------------------------------------------------
# 编码类型枚举
# ---------------------------------------------------------------------------

class EncodingType:
    """已知编码类型常量。"""
    BASE64 = "base64"
    BASE64_URLSAFE = "base64_urlsafe"
    HEX = "hex"
    URL = "url"                    # URL 编码 (百分号编码)
    DOUBLE_URL = "double_url"      # 双重 URL 编码
    HTML_ENTITY = "html_entity"    # HTML 实体编码
    UNICODE_ESCAPE = "unicode"     # \\uXXXX 转义
    ROT13 = "rot13"
    QUOTED_PRINTABLE = "qp"        # Quoted-Printable
    ASCII85 = "ascii85"            # Adobe Ascii85 / btoa
    BASE32 = "base32"
    BASE16 = "base16"              # 同 Hex


# ---------------------------------------------------------------------------
# 编码检测器
# ---------------------------------------------------------------------------

# 正则模式：用启发式检测编码类型
_ENCODING_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Base64: A-Za-z0-9+/= 且长度是4的倍数 (>=8)
    (re.compile(r"^(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$"),
     EncodingType.BASE64),
    # Base64 URLSafe: A-Za-z0-9-_= same
    (re.compile(r"^(?:[A-Za-z0-9\-_]{4})+(?:[A-Za-z0-9\-_]{2}==|[A-Za-z0-9\-_]{3}=)?$"),
     EncodingType.BASE64_URLSAFE),
    # Hex: 纯 0-9a-fA-F 且长度偶数
    (re.compile(r"^[0-9a-fA-F]+$"), EncodingType.HEX),
    # Base32: A-Z2-7=  (RFC 4648)
    (re.compile(r"^[A-Z2-7=]+$"), EncodingType.BASE32),
    # URL 编码: %XX
    (re.compile(r"(%[0-9a-fA-F]{2})+"), EncodingType.URL),
    # Unicode 转义: \\uXXXX
    (re.compile(r"\\u[0-9a-fA-F]{4}"), EncodingType.UNICODE_ESCAPE),
    # HTML 实体: &#xxx; 或 &xxx;
    (re.compile(r"&\w+;|&#\d+;|&#x[0-9a-fA-F]+;"), EncodingType.HTML_ENTITY),
    # ASCII85: 以 <~ 开头或包含非标准Base64字符
    (re.compile(r"<~[!-u]+~>"), EncodingType.ASCII85),
]


def detect_encoding(text: str) -> list[str]:
    """智能检测文本可能的编码类型。

    Args:
        text: 待检测的文本。

    Returns:
        按可能性降序排列的编码类型列表（可能为空）。
    """
    if not text or not isinstance(text, str):
        return []

    text_stripped = text.strip()
    if not text_stripped:
        return []

    results: list[str] = []

    for pattern, enc_type in _ENCODING_PATTERNS:
        if pattern.search(text_stripped):
            # 对 Base64 加长度检查：至少 8 字符
            if enc_type in (EncodingType.BASE64, EncodingType.BASE64_URLSAFE):
                if len(text_stripped) < 8:
                    continue
            results.append(enc_type)

    # URL 编码启发式：如果 %XX 占比超过 20%，认为是 URL 编码
    if EncodingType.URL in results:
        pct_count = len(re.findall(r"%[0-9a-fA-F]{2}", text_stripped))
        if pct_count < 2 and len(text_stripped) > 10:
            results.remove(EncodingType.URL)

    return results


# ---------------------------------------------------------------------------
# 编码转换器
# ---------------------------------------------------------------------------

def try_decode(text: str, encoding: str) -> str | None:
    """尝试用指定编码解码文本，失败返回 None。

    Args:
        text: 待解码的文本。
        encoding: 编码类型（EncodingType 常量之一）。

    Returns:
        解码后的文本，或 None。
    """
    if not text:
        return text

    try:
        text_stripped = text.strip()
        if encoding == EncodingType.BASE64:
            # JWT and many web tokens omit padding; restore it
            raw = base64.b64decode(text_stripped + "=" * ((4 - len(text_stripped) % 4) % 4))
            return _bytes_to_str(raw)
        elif encoding == EncodingType.BASE64_URLSAFE:
            raw = base64.urlsafe_b64decode(text_stripped + "=" * ((4 - len(text_stripped) % 4) % 4))
            return _bytes_to_str(raw)
        elif encoding == EncodingType.HEX:
            raw = binascii.unhexlify(text.strip())
            return _bytes_to_str(raw)
        elif encoding == EncodingType.URL:
            return urllib.parse.unquote(text)
        elif encoding == EncodingType.DOUBLE_URL:
            return urllib.parse.unquote(urllib.parse.unquote(text))
        elif encoding == EncodingType.HTML_ENTITY:
            return html.unescape(text)
        elif encoding == EncodingType.UNICODE_ESCAPE:
            return text.encode("utf-8").decode("unicode_escape")
        elif encoding == EncodingType.ROT13:
            return text.translate(str.maketrans(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
            ))
        elif encoding == EncodingType.QUOTED_PRINTABLE:
            raw = quopri.decodestring(text.encode("utf-8"))
            return _bytes_to_str(raw)
        elif encoding == EncodingType.ASCII85:
            raw = base64.a85decode(text.encode("utf-8"))
            return _bytes_to_str(raw)
        elif encoding == EncodingType.BASE32:
            raw = base64.b32decode(text.strip())
            return _bytes_to_str(raw)
        elif encoding == EncodingType.BASE16:
            raw = binascii.unhexlify(text.strip())
            return _bytes_to_str(raw)
    except Exception:
        return None
    return None


def auto_decode(text: str, max_depth: int = 3) -> list[dict[str, Any]]:
    """自动检测并解码，支持多层嵌套解码（如 Base64 里包 URL 编码）。

    Args:
        text: 待解码的文本。
        max_depth: 最大递归解码层数。

    Returns:
        按解码顺序排列的结果列表，每项包含:
        ``{"layer": int, "encoding": str, "result": str, "is_json": bool}``
    """
    results: list[dict[str, Any]] = []
    current = text

    for layer in range(max_depth):
        encodings = detect_encoding(current)
        if not encodings:
            break

        best = encodings[0]
        decoded = try_decode(current, best)
        if decoded is None or decoded == current:
            break

        is_json = _looks_like_json(decoded)
        results.append({
            "layer": layer + 1,
            "encoding": best,
            "result": decoded,
            "is_json": is_json,
        })
        current = decoded

        # 如果解码出 JSON，尝试解析并展示结构
        if is_json:
            try:
                parsed = json.loads(decoded)
                results[-1]["parsed"] = parsed
            except json.JSONDecodeError:
                pass

    return results


# ---------------------------------------------------------------------------
# 编码函数
# ---------------------------------------------------------------------------

def encode(text: str, encoding: str) -> str:
    """用指定编码编码文本。

    Args:
        text: 原始文本。
        encoding: 目标编码类型。

    Returns:
        编码后的文本。

    Raises:
        ValueError: 不支持的编码类型。
    """
    raw_bytes = text.encode("utf-8")

    if encoding == EncodingType.BASE64:
        return base64.b64encode(raw_bytes).decode("ascii")
    elif encoding == EncodingType.BASE64_URLSAFE:
        return base64.urlsafe_b64encode(raw_bytes).decode("ascii")
    elif encoding == EncodingType.HEX:
        return binascii.hexlify(raw_bytes).decode("ascii")
    elif encoding == EncodingType.URL:
        return urllib.parse.quote(text)
    elif encoding == EncodingType.DOUBLE_URL:
        return urllib.parse.quote(urllib.parse.quote(text))
    elif encoding == EncodingType.ROT13:
        return text.translate(str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
        ))
    elif encoding == EncodingType.HTML_ENTITY:
        return html.escape(text, quote=True)
    elif encoding == EncodingType.BASE32:
        return base64.b32encode(raw_bytes).decode("ascii")
    else:
        raise ValueError(f"unsupported encoding type: {encoding}")


# ---------------------------------------------------------------------------
# 哈希工具
# ---------------------------------------------------------------------------

def hash_text(text: str, algorithm: str = "md5") -> str:
    """计算文本的哈希值。

    Args:
        text: 待哈希文本。
        algorithm: 哈希算法 (md5/sha1/sha256/sha512)。

    Returns:
        十六进制哈希字符串。
    """
    raw = text.encode("utf-8")
    if algorithm == "md5":
        return hashlib.md5(raw).hexdigest()
    elif algorithm == "sha1":
        return hashlib.sha1(raw).hexdigest()
    elif algorithm == "sha256":
        return hashlib.sha256(raw).hexdigest()
    elif algorithm == "sha512":
        return hashlib.sha512(raw).hexdigest()
    else:
        raise ValueError(f"unknown hash algorithm: {algorithm}")


# ---------------------------------------------------------------------------
# 时间戳工具 — 逆向中常见的时间格式转换
# ---------------------------------------------------------------------------

# 常见 Unix 时间戳前缀（毫秒 vs 秒）
# 如果时间戳 > 10000000000 (> 2001-04-24)，很可能是毫秒
_MILLIS_THRESHOLD = 10000000000


def analyze_timestamp(ts: int | str) -> dict[str, Any]:
    """分析一个时间戳，返回多种解读。

    自动检测秒/毫秒/微秒级时间戳，以及常见 Web 时间格式。

    Args:
        ts: 时间戳数值或可转换为数值的字符串。

    Returns:
        包含多种解读的 dict。
    """
    try:
        ts_val = int(str(ts).strip())
    except (ValueError, TypeError):
        return {"error": f"not a valid timestamp: {ts}"}

    result: dict[str, Any] = {"original": ts_val}

    # 检测精度
    if ts_val > _MILLIS_THRESHOLD * 1000:
        # 微秒级
        seconds = ts_val / 1_000_000
        result["precision"] = "microseconds"
    elif ts_val > _MILLIS_THRESHOLD:
        seconds = ts_val / 1000
        result["precision"] = "milliseconds"
    else:
        seconds = float(ts_val)
        result["precision"] = "seconds"

    # 转换为各种格式
    try:
        dt_obj = dt.datetime.fromtimestamp(seconds, tz=dt.timezone.utc)
        result["utc_iso"] = dt_obj.isoformat()
        result["utc_readable"] = dt_obj.strftime("%Y-%m-%d %H:%M:%S UTC")
        result["unix_seconds"] = int(seconds)
        # 常见 Web 格式
        result["http_date"] = dt_obj.strftime("%a, %d %b %Y %H:%M:%S GMT")
        result["cookie_date"] = dt_obj.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
        # JS Date.getTime() 格式（毫秒）
        result["js_timestamp"] = int(seconds * 1000)
        # 年月日分解
        result["ymd"] = dt_obj.strftime("%Y-%m-%d")
        result["time_of_day"] = dt_obj.strftime("%H:%M:%S")
    except (OSError, ValueError, OverflowError) as exc:
        result["error"] = str(exc)

    return result


def generate_timestamp(style: str = "unix") -> int | str:
    """生成符合某种风格的时间戳（用于请求伪造）。

    Args:
        style: "unix" (秒), "js" (毫秒), "iso", "http_date", "cookie_date"

    Returns:
        对应风格的时间戳值。
    """
    now = dt.datetime.now(dt.timezone.utc)

    if style == "unix":
        return int(now.timestamp())
    elif style == "js":
        return int(now.timestamp() * 1000)
    elif style == "iso":
        return now.isoformat()
    elif style == "http_date":
        return now.strftime("%a, %d %b %Y %H:%M:%S GMT")
    elif style == "cookie_date":
        return now.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
    else:
        raise ValueError(f"unknown timestamp style: {style}")


# ---------------------------------------------------------------------------
# 内部工具
# ---------------------------------------------------------------------------

def _bytes_to_str(raw: bytes) -> str:
    """尝试用常用编码解码 bytes，自动检测 UTF-8/GBK/Shift-JIS。"""
    for enc in ("utf-8", "gbk", "shift_jis", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return raw.decode("utf-8", errors="replace")


def _looks_like_json(text: str) -> bool:
    """判断文本是否看起来像 JSON。"""
    text = text.strip()
    return (text.startswith("{") and text.endswith("}")) or (
        text.startswith("[") and text.endswith("]")
    )


# ---------------------------------------------------------------------------
# 综合解码器 — 一键逆向常见数据格式
# ---------------------------------------------------------------------------

def decode_jwt(token: str) -> dict[str, Any] | None:
    """解码 JWT Token 的 Header 和 Payload（不验证签名）。

    JWT 格式: header.payload.signature（Base64 URLSafe 编码）。

    Args:
        token: JWT 字符串。

    Returns:
        {"header": ..., "payload": ..., "signature": ...} 或 None。
    """
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None

    result: dict[str, Any] = {}
    for name, part in zip(("header", "payload", "signature"), parts):
        decoded = try_decode(part, EncodingType.BASE64_URLSAFE)
        if decoded and name != "signature":
            try:
                result[name] = json.loads(decoded)
            except json.JSONDecodeError:
                result[name] = decoded
        else:
            result[name] = part  # 签名保留原样

    return result


def decode_set_cookie(cookie_str: str) -> dict[str, Any]:
    """解析 Set-Cookie 头部字段。

    Args:
        cookie_str: Set-Cookie 原始字符串。

    Returns:
        {"name": ..., "value": ..., "attributes": {attr: value}}。
    """
    parts = cookie_str.split(";")
    name_val = parts[0].strip().split("=", 1)
    result: dict[str, Any] = {
        "name": name_val[0].strip() if name_val else "",
        "value": name_val[1].strip() if len(name_val) > 1 else "",
        "attributes": {},
    }

    for attr in parts[1:]:
        attr = attr.strip()
        if "=" in attr:
            k, v = attr.split("=", 1)
            result["attributes"][k.lower().strip()] = v.strip()
        else:
            result["attributes"][attr.lower()] = True

    return result
