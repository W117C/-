# SecAgent — 项目架构文档

## 定位

**安全导向的 MCP 服务器**，将开源安全工具（subfinder/httpx/nuclei/gitleaks/theHarvester）
包装成 MCP 工具，供 AI Agent（Claude Code / Codex）调用。

同时内置 **Web 逆向分析工具集**（JS 反混淆/签名分析/Cookie 分析/流量分析），用于
对 Web 应用进行全链路逆向工程。

---

## 分层架构

```
┌─────────────────────────────────────────────────────────────────────┐
│                      MCP Clients (Claude Code / Codex)              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │ stdio
┌───────────────────────────────▼─────────────────────────────────────┐
│  CLI Layer (cli/)                 │  MCP Transport (server/__main__) │
│  ├ authz — 授权管理               │  └ MCP stdio 协议适配             │
│  ├ audit — 审计查询               │                                  │
│  ├ findings — 结果查询            │                                  │
│  └ report — 报告生成             │                                  │
├───────────────────────────────────┼──────────────────────────────────┤
│  Application Core (server/app.py)                                    │
│  ├ list_tools() — 工具列表        │  无 MCP SDK 依赖，可独立测试      │
│  ├ call_tool() — 工具分发         │  输入校验 + 错误映射              │
│  ├ submit_scan() — 异步提交       │                                  │
│  └ poll_result() — 结果轮询       │                                  │
├──────────────────────────────────────────────────────────────────────┤
│  Tools Registry (server/tools_registry.py)                           │
│  └ 9 个 ToolDefinition: enumerate_subdomains / scan_ports / ...      │
├──────────────────────────────────────────────────────────────────────┤
│  ComplianceGate (core/gate.py) — 四层合规防线                        │
│  ┌─────────────────────────────────────────────────────────────────┐ │
│  │ ① 授权校验  → token 存在 + 已验证 + 目标在 scope 内             │ │
│  │ ② 黑名单    → .gov/.mil/内网 IP/自定义封禁域名                  │ │
│  │ ③ DNS 防御  → 解析 hostname → 逐个检查解析 IP 是否在黑名单      │ │
│  │ ④ 配额控制  → 原子递减 (事务内)                                  │ │
│  │ ⑤ 审计日志  → SHA-256 哈希链，防篡改，append-only               │ │
│  └─────────────────────────────────────────────────────────────────┘ │
├──────────────────────────────────────────────────────────────────────┤
│  Agent Dispatcher (core/dispatcher.py) — 并行编排层                  │
│  ├ ThreadPoolExecutor 并行执行多个扫描任务                            │
│  ├ 跨任务结果去重 (type, target, title)                             │
│  └ 自动 enrich: confidence + remediation 注入                       │
├──────────────────────────────────────────────────────────────────────┤
│  Remediation KB (core/remediation.py) — 修复建议知识库               │
│  ├ 18 条规则 (Critical→Low) 按模式匹配                              │
│  └ Confidence scoring: validated / likely / unvalidated             │
├──────────────────────────────────────────────────────────────────────┤
│  Tool Functions (tools/ 16 个)        │  Analyzers (analyzers/ 8 个)       │
│  渗透扫描 (11):                       │  逆向分析工具集:                    │
│  ├ enumerate_subdomains.py (subfinder) │  ├ js_reverser.py (JS 反混淆)      │
│  ├ scan_ports.py (naabu, 并行)        │  ├ cookie_analyzer.py (JWT/Cookie) │
│  ├ probe_services.py (httpx)          │  ├ api_signer.py (API 签名分析)    │
│  ├ discover_paths.py (ffuf)           │  ├ traffic_analyzer.py (HAR 分析)  │
│  ├ scan_vulnerabilities.py (nuclei)   │  ├ web_scraper.py (高级爬虫)       │
│  ├ gather_osint.py (theHarvester)     │  ├ binary_analyzer.py (PE/ELF)     │
│  ├ scan_secret_leaks.py (gitleaks)    │  └ cli_reverser.py (AI CLI 逆向)  │
│  ├ crawl_target.py (内置爬虫)         │                                    │
│  ├ crawl_with_katana.py (katana 深度) │                                    │
│  ├ resolve_dns.py (dnsx, 泛域名检测)  │                                    │
│  ├ fingerprint_tls.py (tlsx, JA3/JA4)│                                    │
│  ├ search_engines.py (uncover 聚合)   │                                    │
│  ├ passive_recon.py (crt.sh 等)       │                                    │
│  ├ attack_surface_scan.py (7 相编排)  │                                    │
│  └ check_health.py (健康检查)         │                                    │
├──────────────────────────────────────────────────────────────────────┤
│  Adapters Layer (adapters/ 14 个)                                      │
│  ├ BaseAdapter (ABC)                                                   │
│  ├ 渗透工具: Subfinder / Naabu / Httpx / Ffuf / Nuclei / Gitleaks     │
│  │           TheHarvester / SimpleCrawler                              │
│  ├ 新工具:   Katana (深度爬虫) / Dnsx (DNS) / Tlsx (TLS) / Uncover    │
│  │           (搜索引擎聚合)                                            │
│  └ Launcher (binmgmt/) — 二进制发现 + 子进程执行 + 代理注入          │
├──────────────────────────────────────────────────────────────────────┤
│  Proxy Manager (core/proxy.py) — 三层匿名防护                          │
│  ├ Gate.proxy_manager → @gated_tool → Launcher(proxy_manager=...)     │
│  ├ 9 个工具自动注入 -proxy 标志或 ALL_PROXY 环境变量                  │
│  ├ DNS 解析走 SOCKS5 remote-DNS (gate._resolve_with_timeout)          │
│  ├ UA 伪装: random_ua("chrome_mac") 替代所有硬编码                    │
│  └ 代理池: round_robin / random + 健康检查 + 死节点剔除               │
├──────────────────────────────────────────────────────────────────────┤
│  Storage (storage/sqlite_store.py)                                   │
│  ├ SQLite: authorizations / quota / findings / audit_log / jobs     │
│  ├ 事务支持 (store.transaction())                                   │
│  └ 迁移脚本 (migrations/)                                          │
├──────────────────────────────────────────────────────────────────────┤
│  Shared Modules (core/)                                              │
│  ├ proxy.py     — 代理池管理 (SOCKS5/HTTP, 轮换/随机)              │
│  ├ errors.py    — 统一错误模型 (6 种 ErrorCode)                     │
│  ├ decoders.py  — 编解码工具 (Base64/Hex/URL/JWT/Hash)             │
│  ├ headers.py   — HTTP 头分析 (UA 指纹/请求头伪造)                 │
│  ├ finding.py   — Finding 数据模型                                  │
│  ├ scheduler.py — 异步任务调度 (submit → 后台线程 → poll)          │
│  └ config.py    — YAML 配置加载 + 环境变量覆盖                     │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 数据流

### 1. 安全扫描（主流程）

```
用户请求 → MCP Client
  │
  ▼
server/__main__.py (MCP stdio transport)
  │
  ▼
server/app.py :: call_tool(name, args)
  │
  ├─ 输入校验 (required args + type check)
  │
  ▼
tools_registry.py :: handler(gate, args)
  │
  ▼
tools/*.py :: tool_function(gate, params, authz_token, caller_id)
  │
  ├─ gate.check() ─── 授权/黑名单/DNS/配额 → 通过则继续
  │
  ▼
adapters/*.py :: adapter.run(params)
  │
  ├─ binmgmt/launcher.py :: Launcher.run(cmd)
  │
  ├─ 子进程执行外部工具 (subfinder/httpx/nuclei/...)
  │
  ▼
解析输出 → list[Finding]
  │
  ▼
gate.commit_findings() ─── 配额递减 + 持久化 + 审计日志
  │
  ▼
返回 JSON 结果 → MCP Client
```

### 2. Web 逆向分析（独立流程）

```
Python 脚本 / 直接调用
  │
  ▼
from secagent.analyzers import ...
  │
  ├─ js_reverser: beautify / detect_obfuscation / extract_sensitive
  ├─ cookie_analyzer: analyze_jwt / detect_token_type / assess_token_security
  ├─ api_signer: detect_signature_params / compute_sign / brute_force_sign_algorithm
  ├─ traffic_analyzer: parse_har / analyze_traffic_flow
  ├─ web_scraper: ScraperConfig / RequestInterceptor / SessionManager
  └─ binary_analyzer: analyze_binary / extract_strings / disassemble_function

共享基础模块:
  ├─ core/decoders: auto_decode / try_decode / hash_text
  └─ core/headers: parse_ua / fingerprint_headers / random_ua
```

---

## 目录结构

```
secagent/
├── src/secagent/               # 核心包
│   ├── __init__.py             # 版本号
│   ├── config.py               # YAML 配置加载
│   │
│   ├── core/                   # 共享核心模块 (17 files)
│   │   ├── gate.py             # ComplianceGate (四层防线 + DNS SOCKS5)
│   │   ├── proxy.py            # ProxyManager (SOCKS5/HTTP, 代理池, 轮换)
│   │   ├── authz.py            # 授权范围 + 校验
│   │   ├── blocklist.py        # 黑名单 (.gov/内网/自定义)
│   │   ├── audit.py            # 哈希链审计日志
│   │   ├── quota.py            # 配额管理 (事务内原子递减)
│   │   ├── registry.py         # Token 发行/吊销
│   │   ├── dispatcher.py       # AgentDispatcher 并行编排 + 去重
│   │   ├── remediation.py      # 修复知识库 (18 规则) + 置信度
│   │   ├── errors.py           # 统一错误模型 (6 种 ErrorCode)
│   │   ├── finding.py          # Finding 数据模型 (confidence + remediation)
│   │   ├── decoders.py         # 编解码 (Base64/Hex/JWT/Hash)
│   │   ├── headers.py          # HTTP 头伪造 + random_ua()
│   │   ├── decorators.py       # @gated_tool + standard_adapter_tool
│   │   ├── tech_paths.py       # 技术栈感知路径映射
│   │   ├── scheduler.py        # 异步任务调度
│   │   └── waf_detect.py       # WAF/CDN 检测
│   │
│   ├── server/                 # MCP 服务器
│   │   ├── __init__.py
│   │   ├── __main__.py         # stdio transport 入口
│   │   ├── app.py              # SecAgentServer 应用核心
│   │   └── tools_registry.py   # 工具注册表 (schema + handler)
│   │
│   ├── tools/                  # 工具函数 (门控入口)
│   │   ├── enumerate_subdomains.py
│   │   ├── scan_ports.py
│   │   ├── scan_vulnerabilities.py
│   │   ├── probe_services.py
│   │   ├── gather_osint.py
│   │   ├── attack_surface_scan.py
│   │   ├── passive_recon.py
│   │   ├── discover_paths.py
│   │   ├── crawl_target.py
│   │   ├── scan_secret_leaks.py
│   │   ├── scan_secret_leaks.py
│   │   └── check_health.py      # 环境健康检查
│   │
│   ├── adapters/               # 外部工具适配器 (14 个)
│   │   ├── base.py             # BaseAdapter (ABC)
│   │   ├── subfinder.py        # SubfinderAdapter
│   │   ├── naabu.py            # NaabuAdapter
│   │   ├── httpx_adapter.py    # HttpxAdapter
│   │   ├── nuclei.py           # NucleiAdapter
│   │   ├── ffuf.py             # FfufAdapter
│   │   ├── gitleaks.py         # GitleaksAdapter
│   │   ├── theharvester.py     # TheHarvesterAdapter
│   │   ├── simple_crawler.py   # SimpleCrawlerAdapter
│   │   ├── katana.py           # KatanaAdapter (深度爬虫)
│   │   ├── dnsx.py             # DnsxAdapter (DNS 解析)
│   │   ├── tlsx.py             # TlsxAdapter (TLS 指纹)
│   │   └── uncover.py          # UncoverAdapter (搜索引擎聚合)
│   │
│   ├── analyzers/              # Web 逆向分析工具集
│   │   ├── __init__.py         # 统一导出
│   │   ├── js_reverser.py      # JS 反混淆
│   │   ├── cookie_analyzer.py  # Cookie/JWT 分析
│   │   ├── api_signer.py       # API 签名分析
│   │   ├── traffic_analyzer.py # 流量分析 (HAR)
│   │   ├── web_scraper.py      # 高级爬虫 (Playwright)
│   │   └── binary_analyzer.py  # 二进制分析 (PE/ELF)
│   │
│   ├── cli/                    # Click CLI
│   │   ├── __init__.py         # main() 入口
│   │   ├── authz.py
│   │   ├── audit.py
│   │   ├── findings.py
│   │   └── report.py
│   │
│   ├── binmgmt/                # 二进制管理
│   │   ├── installer.py
│   │   ├── launcher.py
│   │   └── versions.py
│   │
│   ├── storage/                # 持久化层
│   │   ├── sqlite_store.py
│   │   └── migrations/
│   │
│   ├── report/                 # 报告生成
│   │   ├── _common.py          # 共享工具函数
│   │   ├── markdown_report.py  # Markdown 报告 (含 confidence + remediation)
│   │   └── json_report.py      # JSON 报告
│   │
│   └── wordlists/              # 字典文件 (paths_builtin.txt + common.txt)
│
├── scripts/
│   ├── install.sh              # 二进制工具安装
│   ├── install.ps1             # Windows 安装
│   └── reverse/                # 逆向分析示例脚本
│       ├── reverse_bilibili.py
│       ├── reverse_codex.py
│       ├── analyze_claude_detection.py
│       └── aihot_reverse.py
│
├── tests/                      # 测试套件
│   ├── conftest.py
│   └── test_*.py               # 661 测试
│   ├── run_real_targets.py     # 真实目标集成测试
│
├── docs/                       # 文档
│   ├── QUICKSTART.md
│   ├── MCP_SERVER.md
│   ├── AUTHORIZATION.md
│   └── COMPLIANCE.md
│
├── data/                       # 运行时数据
├── bin/                        # 下载的工具二进制
├── vendor/                     # 第三方工具 (theHarvester)
├── .github/workflows/           # CI/CD
│   └── security-scan.yml        # GitHub Actions 自动扫描
│
├── ARCHITECTURE.md             # 本文件
├── README.md
├── pyproject.toml
├── config.example.yaml
└── Makefile                    # install/test/server/reverse/health-check/update-templates/clean
```

---

## 关键设计决策

### 1. 四层合规防线

每一条工具调用都必须通过 ComplianceGate 的五道检查，任何一道失败即拒绝执行并记录审计日志。
审计日志使用 SHA-256 哈希链（每行的 hash = sha256(上一行hash || 本行字段)），任何篡改可被检测。

### 2. 同步/异步工具分离

快速工具（enumerate_subdomains, scan_secret_leaks 等）直接在 MCP handler 中同步执行。
慢速工具（scan_vulnerabilities, attack_surface_scan 等）通过 submit_scan/poll_result 异步执行，
避免 MCP 超时。

### 3. Analyzers 独立性

`analyzers/` 是 Web 逆向分析工具集，与安全扫描（adapters/tools）是**正交的两套能力**：
- 安全扫描：需要授权、黑名单、配额、审计
- 逆向分析：直接调用，无需合规门控

两者共享 `core/decoders.py` 和 `core/headers.py` 作为基础模块。

### 4. 代理管理

ProxyManager 支持四种代理模式：
1. CLI 原生标志注入（subfinder -proxy, nuclei -proxy）
2. ALL_PROXY 环境变量
3. Python urllib ProxyHandler
4. PySocks 全局 socket 覆盖（SOCKS5）

---

## 扩展新工具

1. 在 `tools/` 创建工具函数，签名 `tool_fn(gate, params, authz_token, caller_id)`
2. 在 `adapters/` 创建适配器，继承 `BaseAdapter`
3. 在 `server/tools_registry.py` 添加 `ToolDefinition`（name + schema + handler）
4. 无需修改 `server/app.py` 或 `__main__.py`

---

## 运行命令

```bash
# 安装
make install

# 运行测试
make test

# 健康检查
make health-check

# 更新 Nuclei 模板
make update-templates

# 启动 MCP 服务器
make server

# 启动 CLI
secagent --help

# 逆向分析示例
make reverse

# 并行编排扫描
python -c "
from secagent.core.dispatcher import AgentDispatcher, Task
from secagent.core.gate import ComplianceGate
d = AgentDispatcher(ComplianceGate(), 'token', 'cli')
r = d.dispatch([
    Task('enumerate_subdomains', {'target_domain': 'example.com'}, priority=10),
    Task('scan_ports', {'target': 'example.com'}, priority=5),
])
print(r['summary'])
"
```
