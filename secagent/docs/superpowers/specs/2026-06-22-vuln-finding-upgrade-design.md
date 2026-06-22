# SecAgent 漏洞发现能力优化升级 — 设计方案

> 2026-06-22 | 基于三智能体交叉审核后定稿

---

## 一、概述

### 1.1 目标

在 SecAgent 现有 7 个工具（子域名枚举、服务探测、Nuclei 扫描、OSINT、密泄露、爬虫、攻击面链）的基础上，**定向增强端口扫描、目录模糊测试和被动侦察**三个能力维度，填补当前漏洞发现链的关键空白。

### 1.2 成功标准

1. 新增 2 个工具 + 1 个增强工具，全部通过 ComplianceGate 合规防护
2. 所有新增工具注册到 MCP（同步 + 异步 submit/poll）
3. 升级 `attack_surface_scan` 链覆盖新能力
4. 安全加固（DNS IP 检查、速率限制、路径作用域）已集成
5. 226+ 现有测试继续通过，新增工具测试覆盖

### 1.3 不做的（此批次）

| 项目 | 原因 |
|------|------|
| CVE 关联 (correlate_vulns) | 移到报告层，后续批次做 |
| Web 截图 (gowitness) | 需要 Chromium，增加复杂度 |
| JS 分析增强 | 依赖 crawl_target 后续迭代 |
| WAF/CDN 检测 | 后续批次 |
| 技术栈感知 fuzz | 后续迭代优化 |

---

## 二、新增工具 ①：`scan_ports` (naabu)

### 2.1 适配器

**文件**: `secagent/src/secagent/adapters/naabu.py`

```python
class NaabuAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "naabu"

    def run(self, params: dict[str, Any]) -> list[Finding]:
        """运行 naabu 端口扫描。

        params:
          - target: str       # 目标域名/IP（必填）
          - ports: str        # 端口范围，默认 '80,443,8080-8090,8443'
          - scan_type: str    # 'syn' 或 'connect'，默认 'connect'
          - rate: int         # 扫描速率，上限 2000，默认 500
          - timeout_sec: int  # 超时，默认 120
        """
```

### 2.2 CLI 参数构建

```
naabu -host {target} -p {ports} -scan-type {scan_type} -rate {rate} -json -silent
```

### 2.3 输出解析 (JSONL)

```json
{"host":"example.com","port":443,"protocol":"tcp","service":"https"}
```

naabu 输出 JSONL（每行一个对象），适配器逐行解析。

### 2.4 Finding 格式

```json
{
  "type": "open_port",
  "severity": "info",
  "target": "example.com",
  "title": "Open port 443/tcp (https)",
  "evidence": {
    "port": 443,
    "protocol": "tcp",
    "service": "https",
    "scan_type": "connect"
  }
}
```

### 2.5 工具函数

**文件**: `secagent/src/secagent/tools/scan_ports.py`

```python
def scan_ports(*, gate, params, authz_token, caller_id) -> dict:
```

- 与现有工具函数签名一致
- 调用 `gate.check()` 进行合规检查
- 调用 `NaabuAdapter.run()`
- 调用 `gate.commit_findings()` 持久化

### 2.6 安全限制

- `rate` 上限 2000 pps（防止 DoS）
- 默认 `scan_type='connect'`（无需 root，`syn` 模式需要警告）
- `gate.check()` 解析目标 DNS 并检查 IP 是否在禁止列表（见§5.1）

---

## 三、新增工具 ②：`discover_paths` (ffuf)

### 3.1 适配器

**文件**: `secagent/src/secagent/adapters/ffuf.py`

```python
class FfufAdapter(BaseAdapter):
    @property
    def tool_name(self) -> str:
        return "ffuf"

    def run(self, params: dict[str, Any]) -> list[Finding]:
        """运行 ffuf 目录/文件模糊测试。

        params:
          - target: str            # 目标 URL，如 'https://example.com/FUZZ'（必填）
          - wordlist: str          # 字典路径，默认使用内置字典
          - extensions: str        # 扩展名 'php,asp,js,bak'
          - recursive: bool        # 是否递归
          - recursive_depth: int   # 递归深度，默认 1，上限 3
          - match_status: str      # 匹配状态码 '200,301,302'
          - threads: int           # 线程数，默认 40，上限 200
          - max_time: int          # 最大秒数，默认 60
          - rate: int              # 请求/秒，上限 500
        """
```

### 3.2 输出解析

ffuf 输出 JSONL（每行一个对象）：

```json
{"url":"https://example.com/admin","status":200,"content_length":3241,"content_type":"text/html","redirect":"","duration":125}
```

适配器逐行解析。

### 3.3 内置字典策略

| 层级 | 来源 | 大小 | 获取方式 |
|------|------|------|---------|
| **内置 (L1)** | `secagent/src/secagent/wordlists/paths_builtin.txt` | ~1200 条 | 随 Python 包安装，`importlib.resources` 加载 |
| **通用 (L2)** | `{wordlists_dir}/common.txt` | ~5000 条 | `install.sh` 下载 |
| **完整 (L3)** | 用户自行提供路径 | 不限 | 用户指定 `wordlist` 参数 |

未部署 L2/L3 时静默回退到内置字典。

### 3.4 Finding 格式

```json
{
  "type": "exposed_path",
  "severity": "medium",
  "target": "https://example.com",
  "title": "Exposed path /admin/login.php (200 - 3.2KB)",
  "evidence": {
    "url": "https://example.com/admin/login.php",
    "status_code": 200,
    "content_type": "text/html",
    "content_length": 3241
  }
}
```

严重度规则：

| 匹配特征 | 严重度 |
|---------|--------|
| `.git/config`, `.env`, `*.sql`, `*.bak`, `~backup` | `critical` |
| `/admin`, `/wp-admin`, `/api/`, `/debug` | `high` |
| `/phpmyadmin`, `/uploads`, `/docs/` | `medium` |
| 其他 200/301/302/401/403 | `low` |
| 其他非 404 | `info` |

### 3.5 工具函数

**文件**: `secagent/src/secagent/tools/discover_paths.py`

```python
def discover_paths(*, gate, params, authz_token, caller_id) -> dict:
```

### 3.6 安全限制

| 限制项 | 值 | 说明 |
|--------|-----|------|
| `rate` | 上限 500/s，**默认 100/s** | 防止 WAF 触发 |
| `recursive_depth` | 上限 3 | 防止递归爆炸 |
| `max_time` | 上限 300s | 防止长期占用 |
| `wordlist` 大小 | 上限 20000 条 | 防止内存溢出 |

### 3.7 wordlists_dir 配置

新增配置项，继承 `binaries_dir` 模式：

```yaml
# 环境变量或 config.yaml
SECAGENT_WORDLISTS_DIR=./wordlists
```

**文件**: `secagent/src/secagent/config.py` 新增字段

---

## 四、增强 ③：被动侦察 — `gather_osint` 扩展

### 4.1 现有情况

`gather_osint` 只包装 theHarvester，数据源受限于 theHarvester 的支持列表。

### 4.2 增强方式

在新的被动侦察工具中整合更多数据源，而不是改 theHarvester 适配器：

**文件**: 新增 `secagent/src/secagent/tools/passive_recon.py`

| 数据源 | 类型 | 集成方式 |
|--------|------|---------|
| crt.sh | 证书透明度 | HTTP API → 自定义适配器 |
| SecurityTrails | 被动 DNS | HTTP API → 自定义适配器（可选 API key） |
| Shodan | 互联网测绘 | HTTP API → 自定义适配器（可选 API key） |
| theHarvester | OSINT | 复用现有适配器 |

这些数据源作为**可选增强**，无 API key 时静默降级。

### 4.3 架构说明

被动侦察工具**不**使用 `BaseAdapter`（BaseAdapter 设计用于 CLI 二进制子进程）。`passive_recon.py` 直接在工具函数中使用 `urllib.request` / `requests` 调用 HTTP API。

**文件**: `tools/passive_recon.py`（无对应 `adapters/` 文件）

### 4.4 API Key 安全处理

| 数据源 | API Key 要求 | 环境变量 | Key 存储原则 |
|--------|-------------|---------|-------------|
| crt.sh | 不需要 | — | 无风险 |
| SecurityTrails | 可选 | `SECAGENT_SECURITYTRAILS_KEY` | 仅环境变量，永不出现在日志/错误/进程列表 |
| Shodan | 可选 | `SECAGENT_SHODAN_KEY` | 同上 |

约束：
- API Key **仅通过环境变量**传入，不使用配置文件
- 通过 HTTP Header 传递（`APIKEY: xxx`），不放在 URL 查询参数中（防 `ps aux` 泄露）
- 原始 API 响应在存入 `evidence` 前擦除可能带有的 Key

---

## 五、安全加固

### 5.1 DNS 解析 IP 检查 (gate.check 增强)

**背景**: 多智能体审核发现 `gate.check()` 只检查主机名字符串，如果目标 hostname 解析到私有 IP（如 `internal.corp.com -> 10.0.0.5`），禁止列表不会拦截。

**改动**: `gate.check()` 新增 DNS 解析步骤：

```python
# 在 blocklist.check(target) 之后
import socket
import logging
log = logging.getLogger(__name__)

# 设置 DNS 超时，防止阻塞 MCP 请求线程
original_timeout = socket.getdefaulttimeout()
socket.setdefaulttimeout(5.0)
try:
    resolved = socket.getaddrinfo(target, None)
    for family, _, _, _, sockaddr in resolved:
        ip = sockaddr[0]
        blocked, reason = self.blocklist.is_blocked(ip)
        if blocked:
            raise ComplianceBlockError(target=ip, reason=reason or "resolved IP blocked")
except socket.gaierror:
    log.warning("DNS resolution failed for %s — skipping IP blocklist check", target)
    # 允许通过：naabu/ffuf 会自己重新解析，失败时报错
finally:
    socket.setdefaulttimeout(original_timeout)
```

### 5.2 路径作用域限制

`discover_paths` 工具函数在调用适配器前验证 URL 路径：

```python
# 拒绝 fuzz 高于配置深度的路径
max_depth = min(params.get("recursive_depth", 1), 3)
if max_depth > 3:
    raise InvalidInputError("recursive_depth", "maximum allowed depth is 3")
```

### 5.3 速率限制继承

所有新建工具继承 `scan_vulnerabilities.py` 的速率限制模式：

```python
requested_rate = int(params.get("rate", 500))
safe_rate = max(1, min(requested_rate, MAX_RATE))  # MAX_RATE 因工具而异
```

### 5.4 naabu CAP_NET_RAW 处理

安装脚本添加 setcap 步骤（有 sudo 时）或打印提示：

```bash
# install.sh 中
if command -v setcap &>/dev/null; then
    sudo setcap cap_net_raw+ep "$BIN_DIR/naabu" 2>/dev/null || \
        echo "Warning: naabu SYN scan requires root/setcap for optimal performance"
fi
```

---

## 六、`attack_surface_scan` 升级

### 6.1 新流水线

```
enum (subfinder)
  → port scan (naabu)
  → probe (httpx，只扫描 naabu 发现端口的端口)
  → path fuzz (ffuf)
  → nuclei scan
  → 报告
```

### 6.2 chain 逻辑修改

```python
# 1. 子域名枚举 (不变)
enum_result = enumerate_subdomains(...)
subdomain_targets = [
    str(f.get("target", ""))
    for f in enum_result.get("findings", [])
    if f.get("target")
]

# （重要）端口扫描覆盖 apex + 所有子域名
all_targets = _dedupe_keep_order([target_domain] + subdomain_targets)

# 2. 端口扫描（扫描所有发现的域名）
port_results = []
for t in all_targets:
    port_result = scan_ports(target=t, ports=...)
    port_results.append(port_result)

# 从 port scan 结果提取 host:port
port_targets = [
    f"{f['target']}:{f['evidence']['port']}"
    for pr in port_results
    for f in pr.get("findings", [])
]

# 3. 服务探测 (只扫开放端口)
probe_params["ports"] = ",".join(set(p.split(":")[1] for p in port_targets))
probe_params["targets"] = list(set(p.split(":")[0] for p in port_targets))
probe_result = probe_services(...)

# 4. 路径模糊测试 (新增)
path_result = discover_paths(target=live_url, wordlist="builtin")

# 5. Nuclei 扫描 (不变)
scan_result = scan_vulnerabilities(...)
```

### 6.3 可选阶段

用户可以通过参数控制是否跳过某些阶段：

```json
{
  "target_domain": "example.com",
  "skip_port_scan": false,
  "skip_path_fuzz": true,
  "max_scan_targets": 10
}
```

---

## 七、文件变更清单

| 文件 | 操作 | 行数估计 |
|------|------|---------|
| `adapters/naabu.py` | **新建** | ~120 |
| `adapters/ffuf.py` | **新建** | ~150 |
| `tools/scan_ports.py` | **新建** | ~90 |
| `tools/discover_paths.py` | **新建** | ~100 |
| `tools/passive_recon.py` | **新建** | ~100 (HTTP API 模式，无 adapter) |
| `tools/attack_surface_scan.py` | **修改** | +100 |
| `server/tools_registry.py` | **修改** | +120 |
| `core/scheduler.py` | **修改** | +6 (调度表) |
| `core/gate.py` | **修改** | +25 (DNS 解析 + IP 检查) |
| `core/finding.py` | **修改** | +4 (FindingType: OPEN_PORT, EXPOSED_PATH) |
| `binmgmt/versions.py` | **修改** | +6 (naabu/ffuf) |
| `binmgmt/installer.py` | **修改** | +10 (二进制列表 + ffuf tar.gz 后缀) |
| `config.py` | **修改** | +5 (wordlists_dir 字段 + env var) |
| `wordlists/__init__.py` | **新建** | ~1 (空文件) |
| `wordlists/paths_builtin.txt` | **新建** | ~1200 (内置字典) |
| `pyproject.toml` | **修改** | +3 (package-data: wordlists) |
| `scripts/install.sh` | **修改** | +3 (naabu setcap 提示) |
| `tests/test_naabu_adapter.py` | **新建** | ~100 |
| `tests/test_ffuf_adapter.py` | **新建** | ~100 |
| `tests/test_scan_ports_tool.py` | **新建** | ~80 |
| `tests/test_discover_paths_tool.py` | **新建** | ~80 |
| `tests/test_passive_recon.py` | **新建** | ~60 |
| `tests/test_attack_surface_scan.py` | **修改** | +30 |
| **Total** | | **~1375 行净增** |

---

## 八、测试策略

| 测试维度 | 方法 |
|---------|------|
| 适配器单元测试 | Mock `_launch`，传入 JSONL 输出，验证 `_parse_output` |
| 工具函数测试 | Mock 适配器，验证 gate.check/commit 调用 |
| 攻击面链测试 | Mock 各阶段，验证编排逻辑 |
| 安全测试 | 验证 gate DNS 检查、速率限制、深度限制 |
| 集成测试 | 用 `conftest.py` 的 fixture 设置 gate + token |

所有测试复用现有模式（`unittest.mock.patch` + `MagicMock`），不依赖真实二进制。

---

## 九、已知风险（此批次不解决）

多智能体审核识别的、不在本批次解决的风险：

| 风险 | 影响 | 缓解措施（后续） |
|------|------|----------------|
| **TOCTOU DNS** — gate.check() 和 adapter.run() 之间的 DNS 可能变化 | 目标 IP 可能在检查后变为私有 IP | naabu 适配器可考虑传入解析后的 IP 而非 hostname；ffuf 需要 URL 难处理 |
| **跨工具速率限制** — 无每令牌滑动窗口速率限制 | 用户可同时运行多个工具导致目标过载 | 后续批次添加 token bucket 限流器 |
| **禁止列表加载失败** — 静默回退到空集合 | 自定义规则丢失 | 当前已有 `log.warning` 和硬编码的私有 IP/政府 TLD 作为兜底 |
| **IPv6 隧道绕过** — 6to4/Teredo 地址 | 可能绕过私有 IP 检查 | 低概率，后续加 `2002::/16` |

---

## 十、不做的事（此批次明确排除）

- Web UI / REST API
- 定时扫描 / 计划任务
- 多用户 / RBAC
- CVE 关联（移到报告层）
- Web 截图
- JS 渲染爬虫
- WAF/CDN 检测
