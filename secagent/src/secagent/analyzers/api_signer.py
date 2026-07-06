"""API 签名逆向分析器 — Web 逆向核心工具。

分析 HTTP 请求中的签名算法、参数排序、摘要计算，并支持
签名复现和请求重放，用于理解目标 API 的认证机制。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any


# 常见的签名参数名称
_SIGNATURE_PARAM_NAMES = {
    "sign", "sig", "signature", "_sign", "_sig",
    "token", "_token", "csrf", "csrf_token",
    "nonce", "_nonce", "salt", "hmac",
    "auth", "authorization", "apikey", "api_key",
    "appkey", "app_key", "appsecret", "secret",
    "checksum", "check_sum", "hash",
    "ts", "timestamp", "_t", "_time", "t",
}


def detect_signature_params(params: dict[str, str]) -> list[str]:
    """从请求参数中检测可能的签名相关参数。"""
    detected = []
    for name in params:
        name_lower = name.lower()
        if name_lower in _SIGNATURE_PARAM_NAMES:
            detected.append(name)
            continue
        for kw in ("sign", "token", "auth", "hash", "key", "secret", "nonce", "hmac"):
            if kw in name_lower:
                detected.append(name)
                break
    return detected


def classify_params(params: dict[str, str]) -> dict[str, list[tuple[str, str]]]:
    """对请求参数进行分类：业务参数 vs 安全参数 vs 元参数。"""
    result: dict[str, list[tuple[str, str]]] = {"business": [], "security": [], "meta": []}
    sig_params = detect_signature_params(params)
    sig_lower = {s.lower() for s in sig_params}
    for key, value in params.items():
        if key.lower() in sig_lower:
            result["security"].append((key, value))
        elif key.lower() in ("callback", "format", "_", "rand", "random"):
            result["meta"].append((key, value))
        else:
            result["business"].append((key, value))
    return result


@dataclass
class SignatureConfig:
    """描述一个 API 的签名规则。"""
    sign_fields: list[str] | None = None
    exclude_fields: list[str] = field(default_factory=lambda: ["sign", "sig", "signature"])
    sort_method: str = "lexical"
    algorithm: str = "md5"
    append_secret: str | None = None
    prepend_secret: str | None = None
    url_encode: bool = False
    uppercase: bool = False
    include_empty: bool = False
    join_char: str = "&"
    trim_values: bool = True


def build_sign_string(params: dict[str, str], config: SignatureConfig) -> str:
    """按指定的签名规则构建待签名字符串。"""
    if config.sign_fields is not None:
        filtered = {k: v for k, v in params.items() if k in config.sign_fields}
    else:
        filtered = dict(params)

    exclude_lower = [e.lower() for e in config.exclude_fields]
    filtered = {k: v for k, v in filtered.items() if k.lower() not in exclude_lower}

    if not config.include_empty:
        filtered = {k: v for k, v in filtered.items() if v}
    if config.trim_values:
        filtered = {k: v.strip() if isinstance(v, str) else v for k, v in filtered.items()}

    if config.sort_method == "lexical":
        items = sorted(filtered.items(), key=lambda x: x[0])
    elif config.sort_method == "sorted_by_key_length":
        items = sorted(filtered.items(), key=lambda x: (len(x[0]), x[0]))
    else:
        items = list(filtered.items())

    if config.url_encode:
        items = [(k, urllib.parse.quote(str(v), safe="")) for k, v in items]

    pairs = [f"{k}={v}" if v else k for k, v in items]
    sign_str = config.join_char.join(pairs)

    if config.append_secret:
        sign_str += config.append_secret
    if config.prepend_secret:
        sign_str = config.prepend_secret + sign_str

    return sign_str


def compute_sign(sign_str: str, algorithm: str, secret: str | None = None) -> str:
    """计算签名摘要。"""
    data = sign_str.encode("utf-8")
    if algorithm.startswith("hmac-"):
        if secret is None:
            raise ValueError(f"HMAC algorithm '{algorithm}' requires a secret")
        h = hmac.new(secret.encode("utf-8"), data, algorithm.replace("hmac-", ""))
        return h.hexdigest()
    else:
        return hashlib.new(algorithm, data).hexdigest()


def brute_force_sign_algorithm(
    params: dict[str, str],
    known_sign: str,
    candidates: list[str] | None = None,
    secrets: list[str | None] | None = None,
) -> list[dict[str, Any]]:
    """暴力枚举签名算法和密钥，寻找匹配的签名配置。"""
    if candidates is None:
        candidates = ["md5", "sha1", "sha256", "sha512", "hmac-md5", "hmac-sha1", "hmac-sha256"]
    if secrets is None:
        secrets = [None, "", "secret", "key", "token", "salt"]

    sign_params = detect_signature_params(params)
    clean_params = {k: v for k, v in params.items() if k not in sign_params}

    results: list[dict[str, Any]] = []
    for algo in candidates:
        for secret in secrets:
            for sort_method in ("lexical", "original"):
                for url_encode in (False, True):
                    for uppercase in (False, True):
                        config = SignatureConfig(
                            algorithm=algo, sort_method=sort_method,
                            url_encode=url_encode, uppercase=uppercase,
                        )
                        sign_str = build_sign_string(clean_params, config)
                        try:
                            computed = compute_sign(sign_str, algo, secret)
                        except ValueError:
                            continue
                        if uppercase:
                            computed = computed.upper()
                        if computed == known_sign:
                            results.append({
                                "algorithm": algo, "secret": secret,
                                "sort_method": sort_method,
                                "url_encode": url_encode,
                                "uppercase": uppercase,
                                "sign_string": sign_str,
                                "computed_sign": computed,
                            })
    return results


@dataclass
class CapturedRequest:
    method: str = ""
    url: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    params: dict[str, str] = field(default_factory=dict)
    body: str | dict[str, Any] | None = None
    cookies: dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class RequestReplayer:
    """请求重放器 — 支持修改参数后重新发送请求。"""

    def __init__(self, captured: CapturedRequest):
        self._captured = captured

    def modify_param(self, key: str, value: str) -> "RequestReplayer":
        self._captured.params[key] = value
        return self

    def modify_header(self, key: str, value: str) -> "RequestReplayer":
        self._captured.headers[key] = value
        return self

    def modify_body(self, body: str | dict[str, Any]) -> "RequestReplayer":
        self._captured.body = body
        return self

    def remove_param(self, key: str) -> "RequestReplayer":
        self._captured.params.pop(key, None)
        return self

    def get_params(self) -> dict[str, str]:
        return dict(self._captured.params)

    def summary(self) -> dict[str, Any]:
        c = self._captured
        return {
            "method": c.method, "url": c.url,
            "params_count": len(c.params), "headers_count": len(c.headers),
            "has_body": c.body is not None,
            "param_names": sorted(c.params.keys()),
            "signature_params": detect_signature_params(c.params),
        }


def analyze_api_auth(captured: CapturedRequest) -> dict[str, Any]:
    """综合分析一个 API 请求的认证机制。"""
    params = captured.params
    classified = classify_params(params)
    sig_params = detect_signature_params(params)

    sign_analysis: list[dict[str, Any]] = []
    for sp in sig_params:
        sp_val = params[sp]
        from secagent.core.decoders import detect_encoding, auto_decode, analyze_timestamp
        encodings = detect_encoding(sp_val)
        decoded_layers = auto_decode(sp_val, max_depth=2)
        is_ts = bool(sp_val.isdigit() and len(sp_val) >= 10)

        entry: dict[str, Any] = {
            "name": sp, "value": sp_val[:80], "length": len(sp_val),
            "looks_like_hash": bool(re.match(r"^[a-f0-9]{32,64}$", sp_val, re.I)),
            "looks_like_base64": "base64" in encodings,
            "is_timestamp": is_ts,
        }
        if decoded_layers:
            entry["decoded"] = decoded_layers[-1]["result"][:100]
        if is_ts:
            entry["timestamp_info"] = analyze_timestamp(sp_val)
        sign_analysis.append(entry)

    return {
        "url": captured.url, "method": captured.method,
        "param_count": len(params),
        "classified_params": {k: [(n, v[:50]) for n, v in v] for k, v in classified.items()},
        "signature_params": sign_analysis,
        "suggested_bruteforce": len(sig_params) > 0 and any(sp["looks_like_hash"] for sp in sign_analysis),
    }
