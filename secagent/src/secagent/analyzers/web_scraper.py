"""高级 Web 爬虫与反反爬 — Web 逆向核心工具。

集成 Playwright 浏览器自动化，支持：
- 浏览器指纹伪装（UA/WebGL/Canvas/Font/Platform）
- 请求拦截与修改（请求头/参数/Cookie 注入）
- 自动等待与渲染等待策略
- Session/Cookie 持久化
- 反检测（webdriver/navigator.chrome 等特征隐藏）
"""
from __future__ import annotations

import json
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable


# ==========================================================================
# 反检测配置
# ==========================================================================

_ANTI_DETECT_JS = """
// 隐藏自动化特征
Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
Object.defineProperty(navigator, 'languages', { get: () => ['zh-CN', 'zh', 'en'] });

// 覆盖 Chrome 特征
window.chrome = { runtime: {} };

// 覆盖权限查询
const originalQuery = navigator.permissions.query;
navigator.permissions.query = (params) => (
  params.name === 'notifications' ? Promise.resolve({ state: 'denied' }) : originalQuery(params)
);
"""

# 常见反爬检测 header
_ANTI_CRAWL_HEADERS: dict[str, str] = {
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
}


@dataclass
class ScraperConfig:
    """爬虫配置。"""
    headless: bool = True
    proxy: str | None = None
    user_agent: str = ""
    viewport: tuple[int, int] = (1920, 1080)
    timeout: int = 30000  # ms
    cookies_file: str = ""
    storage_state_file: str = ""
    extra_headers: dict[str, str] = field(default_factory=dict)
    block_images: bool = False
    block_media: bool = False
    slow_mo: int = 0  # ms 延迟模拟人类


# ==========================================================================
# 请求拦截器
# ==========================================================================

class RequestInterceptor:
    """请求拦截器 — 拦截、修改、记录所有网络请求。

    用于分析 API 调用模式、参数传递、签名算法等。
    """

    def __init__(self):
        self._captured_requests: list[dict[str, Any]] = []
        self._route_rules: list[dict[str, Any]] = []

    def add_block_rule(self, pattern: str) -> None:
        """添加 URL 拦截规则（匹配的请求将被阻止）。"""
        self._route_rules.append({"action": "block", "pattern": pattern})

    def add_abort_rule(self, resource_type: str) -> None:
        """中止指定资源类型的请求（如图片、字体、媒体）。"""
        self._route_rules.append({"action": "abort", "resource_type": resource_type})

    def get_captured(self) -> list[dict[str, Any]]:
        """获取捕获的所有请求。"""
        return list(self._captured_requests)

    def clear(self) -> None:
        """清空捕获记录。"""
        self._captured_requests.clear()

    # Playwright Route 回调
    async def handle_route(self, route) -> None:
        """Playwright route 处理回调。"""
        request = route.request
        url = request.url
        method = request.method

        # 检查拦截规则
        for rule in self._route_rules:
            if rule["action"] == "block":
                if re.search(rule["pattern"], url):
                    await route.abort("blockedbyclient")
                    return
            elif rule["action"] == "abort":
                if request.resource_type == rule["resource_type"]:
                    await route.abort("blockedbyclient")
                    return

        # 捕获请求信息
        entry = {
            "url": url,
            "method": method,
            "headers": dict(request.headers),
            "resource_type": request.resource_type,
            "timestamp": time.time(),
        }

        # 捕获 POST body
        if method == "POST":
            try:
                post_data = request.post_data
                entry["body"] = post_data
            except Exception:
                pass

        self._captured_requests.append(entry)

        # 继续原始请求
        await route.continue_()


# ==========================================================================
# Session Manager
# ==========================================================================

class SessionManager:
    """浏览器会话管理器 — Cookie/Session 持久化和恢复。

    用于在多次爬取之间保持登录态。
    """

    def __init__(self, storage_file: str = ""):
        self._storage_file = storage_file or os.path.expanduser(
            "~/.secagent/scraper_storage.json"
        )
        os.makedirs(os.path.dirname(self._storage_file), exist_ok=True)

    def save(self, storage_state: dict[str, Any]) -> None:
        """保存浏览器会话状态。"""
        with open(self._storage_file, "w", encoding="utf-8") as f:
            json.dump(storage_state, f, ensure_ascii=False, indent=2)

    def load(self) -> dict[str, Any] | None:
        """加载之前保存的浏览器会话状态。"""
        try:
            if os.path.exists(self._storage_file):
                with open(self._storage_file, "r", encoding="utf-8") as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError):
            pass
        return None

    def has_session(self) -> bool:
        """是否有已保存的会话。"""
        return os.path.exists(self._storage_file) and os.path.getsize(self._storage_file) > 10


# ==========================================================================
# 爬虫辅助工具
# ==========================================================================

def generate_mouse_trace(
    start_x: int = 100, start_y: int = 100,
    end_x: int = 500, end_y: int = 300,
    steps: int = 20,
) -> list[dict[str, float]]:
    """生成模拟人类鼠标移动轨迹。

    用于绕过基于鼠标行为分析的 WAF/反爬系统。

    Args:
        start_x, start_y: 起始坐标。
        end_x, end_y: 终点坐标。
        steps: 轨迹点数。

    Returns:
        [{"x": ..., "y": ..., "timestamp": ...}, ...] 轨迹序列。
    """
    import math
    trace = []
    for i in range(steps + 1):
        t = i / steps
        # 贝塞尔曲线插值 + 随机抖动
        x = start_x + (end_x - start_x) * t + random.uniform(-2, 2)
        y = start_y + (end_y - start_y) * t + random.uniform(-2, 2)
        # 加一点点缓动（模拟人类加速/减速）
        eased_t = t * t * (3 - 2 * t)  # smoothstep
        x = start_x + (end_x - start_x) * eased_t + random.uniform(-2, 2)
        y = start_y + (end_y - start_y) * eased_t + random.uniform(-2, 2)
        trace.append({
            "x": round(x, 1),
            "y": round(y, 1),
            "timestamp": i * random.uniform(10, 30),
        })
    return trace


def generate_typing_delay(text: str) -> list[float]:
    """生成模拟人类打字的时间间隔序列。

    用于绕过基于输入行为的反爬检测。

    Args:
        text: 待输入的文本。

    Returns:
        每个字符打字前等待的秒数序列。
    """
    delays = []
    for i, ch in enumerate(text):
        base = random.uniform(0.05, 0.15)
        # 大写字母/数字/符号稍慢
        if ch.isupper() or ch.isdigit():
            base += random.uniform(0.05, 0.1)
        # 逗号/句号后稍停顿
        if ch in ",.!?;:":
            base += random.uniform(0.1, 0.2)
        # 偶而"思考"一下
        if random.random() < 0.05:
            base += random.uniform(0.3, 0.8)
        delays.append(round(base, 3))
    return delays
