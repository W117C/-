"""HTTP 流量捕获与分析 — Web 逆向核心工具。

分析 HTTP 请求/响应模式、请求链、参数传递、Cookie 传递关系，
支持从 HAR 文件导入和请求流程可视化。
"""
from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlparse


@dataclass
class HTTPEntry:
    """一次 HTTP 请求/响应的完整记录。"""
    request_id: str = ""
    method: str = ""
    url: str = ""
    hostname: str = ""
    path: str = ""
    query_params: dict[str, str] = field(default_factory=dict)
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    status_code: int = 0
    response_headers: dict[str, str] = field(default_factory=dict)
    response_body: str | None = None
    content_type: str = ""
    timestamp: float = 0.0
    duration_ms: float = 0.0


@dataclass
class RequestChain:
    """一次页面加载过程中的请求链。"""
    entries: list[HTTPEntry] = field(default_factory=list)
    api_calls: list[HTTPEntry] = field(default_factory=list)
    static_assets: list[HTTPEntry] = field(default_factory=list)
    redirects: list[HTTPEntry] = field(default_factory=list)


def parse_har(har_data: dict[str, Any]) -> list[HTTPEntry]:
    """从 HAR (HTTP Archive) 格式导入请求记录。

    Args:
        har_data: HAR 格式的完整 dict（从浏览器 DevTools 导出）。

    Returns:
        HTTPEntry 列表。
    """
    entries: list[HTTPEntry] = []
    log = har_data.get("log", {})
    raw_entries = log.get("entries", [])

    for raw in raw_entries:
        req = raw.get("request", {})
        resp = raw.get("response", {})

        url = req.get("url", "")
        parsed = urlparse(url)

        # 提取查询参数
        qp = parse_qs(parsed.query, keep_blank_values=True)
        flat_params = {k: v[0] if v else "" for k, v in qp.items()}

        # 请求头
        req_headers = {h.get("name", ""): h.get("value", "") for h in req.get("headers", [])}
        resp_headers = {h.get("name", ""): h.get("value", "") for h in resp.get("headers", [])}

        entry = HTTPEntry(
            request_id=raw.get("_id", str(raw.get("startedDateTime", ""))),
            method=req.get("method", ""),
            url=url,
            hostname=parsed.hostname or "",
            path=parsed.path or "",
            query_params=flat_params,
            request_headers=req_headers,
            request_body=req.get("postData", {}).get("text") if "postData" in req else None,
            status_code=resp.get("status", 0),
            response_headers=resp_headers,
            response_body=resp.get("content", {}).get("text"),
            content_type=resp.get("content", {}).get("mimeType", ""),
            timestamp=raw.get("startedDateTime", ""),
            duration_ms=raw.get("time", 0),
        )
        entries.append(entry)

    return entries


def analyze_traffic_flow(entries: list[HTTPEntry]) -> RequestChain:
    """分析一批请求记录，自动分类为 API 调用、静态资源和重定向。

    Args:
        entries: HTTPEntry 列表。

    Returns:
        分类后的 RequestChain。
    """
    chain = RequestChain(entries=sorted(entries, key=lambda e: e.timestamp))

    for entry in chain.entries:
        # API 调用
        ct = entry.content_type.lower()
        if "json" in ct or "xml" in ct or entry.path.startswith("/api/"):
            chain.api_calls.append(entry)
        # 静态资源
        elif any(ext in entry.path for ext in (".js", ".css", ".png", ".jpg", ".gif", ".svg", ".woff", ".ico")):
            chain.static_assets.append(entry)
        # 重定向
        if entry.status_code in (301, 302, 303, 307, 308):
            chain.redirects.append(entry)

    return chain


def extract_parameter_flow(entries: list[HTTPEntry]) -> dict[str, Any]:
    """分析参数在请求之间的传递关系。

    检测: 从上一个响应的 body/header 中提取的参数值
    是否被用作下一个请求的参数。

    Args:
        entries: HTTPEntry 列表。

    Returns:
        {"param_flow": [...], "tokens": [...], "correlations": [...]}
    """
    param_flow: list[dict[str, Any]] = []
    tokens_found: list[dict[str, Any]] = []
    correlations: list[dict[str, Any]] = []

    # 提取所有 response body 中的值
    response_values: dict[str, set[str]] = {}
    for entry in entries:
        if entry.response_body:
            # 提取 JSON 路径
            try:
                body = json.loads(entry.response_body)
                _extract_json_values(body, "", response_values)
            except json.JSONDecodeError:
                pass

    # 将 response 中的值与后续请求参数做关联
    for i, entry in enumerate(entries):
        for key, value in entry.query_params.items():
            # 检查这个值是否来自之前的 response
            for resp_url, values in response_values.items():
                if value in values:
                    correlations.append({
                        "from_response": resp_url,
                        "to_request": entry.url,
                        "param_name": key,
                        "shared_value": value[:50],
                    })

    return {
        "param_flow": param_flow,
        "tokens": tokens_found,
        "correlations": correlations,
    }


def _extract_json_values(data: Any, prefix: str, result: dict[str, set[str]]) -> None:
    """递归提取 JSON 中所有字符串值。"""
    if isinstance(data, dict):
        for key, value in data.items():
            new_prefix = f"{prefix}.{key}" if prefix else key
            if isinstance(value, str) and len(value) > 8:
                if result.get(prefix) is None:
                    result[prefix] = set()
                result[prefix].add(value)
            else:
                _extract_json_values(value, new_prefix, result)
    elif isinstance(data, list):
        for item in data:
            _extract_json_values(item, f"{prefix}[]", result)
