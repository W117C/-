# SecAgent MCP — 设计文档

- **日期**: 2026-06-16
- **状态**: 已批准（待用户审阅 spec 文件）
- **作者**: brainstorming 会话产出
- **关联项目**: SuperSpider（本仓库）

---

## 1. 背景与目标

### 1.1 一句话定位

把 SuperSpider 爬虫框架 + 开源安全工具（Nuclei/Subfinder/httpx/gitleaks/theHarvester）封装成一套 **MCP Server**，让 Codex / Claude Code / Reasonix 等 agent 通过自然语言驱动"授权资产的安全评估"，以 **B2B 企业订阅 + 持续监控** 为主要变现路径。

### 1.2 方向锁定

| 维度 | 选择 | 说明 |
|---|---|---|
| 网安子方向 | **A 防御型 ASM/EASM + B OSINT 情报** | A 打企业客户，B 打订阅客户，爬虫是共享数据采集层 |
| 能力栈 | **PD 全家桶 + OSINT + 凭证泄露监控**（混合栈 C） | 同时覆盖漏洞/暴露面（A）和情报/泄露（B） |
| 产品形态 | **MCP Server（形态 A）** | 先 MCP，后 SaaS，自研 agent 本体留作未来 |
| MVP tools | **6 个原子 tool**（不做编排 tool） | 编排交给 agent，MCP 只暴露原子能力 |

### 1.3 MVP 成功标准（单一）

一个用户能在 **5 分钟内** 完成：装好 secagent → 登记一个授权资产 → 在 Claude Code 里用自然语言让 agent 跑出一份扫描报告。

---

## 2. 整体架构（5 层）

```
┌─────────────────────────────────────────────────────────────┐
│  层 1 · Agent 客户端                                        │
│  Claude Code / Codex / Reasonix / 任意 MCP 客户端            │
└───────────────────────────┬─────────────────────────────────┘
                            │ MCP 协议（stdio / HTTP+SSE）
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  层 2 · MCP Server（核心产品）                              │
│  6 个 Tools + 通用横切层（鉴权·配额·授权校验·审计·限流）     │
└───────────────────────────┬─────────────────────────────────┘
                            │ 内部调用
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
┌──────────────────┐ ┌────────────┐ ┌──────────────────┐
│ 层 3 · 工具执行器  │ │爬虫框架     │ │  开源工具引擎     │
│ Tool Executor    │ │SuperSpider │ │ Nuclei/Subfinder │
│ 任务编排/超时/重试 │ │pyspider    │ │ httpx/gitleaks   │
└────────┬─────────┘ └─────┬──────┘ └────────┬─────────┘
         └────────┬────────┴─────────────────┘
                  ▼
┌─────────────────────────────────────────────────────────────┐
│  层 4 · 结果与存储层                                         │
│  SQLite（MVP）→ PostgreSQL（生产）· 统一 finding 模型         │
└───────────────────────────┬─────────────────────────────────┘
                            ▼
┌─────────────────────────────────────────────────────────────┐
│  层 5 · 输出与计费                                          │
│  JSON/Markdown 报告 · 调用计量 · 配额扣减                    │
└─────────────────────────────────────────────────────────────┘
```

### 2.1 关键架构决策

1. **封装开源工具，不重写**：Nuclei/Subfinder 是 Go 写的成熟工具，模板社区庞大（8000+）。把它们当**二进制依赖**，带版本锁定 + 校验和。代码只负责"传参 → 跑 → 解析 JSON → 转 Finding"。
2. **SuperSpider 是独立的一条线**：`crawl_target` 调本仓库 pyspider，是差异化壁垒（JS 逆向、反爬、动态渲染）。与开源工具**互补**，在层 3 并列。
3. **统一 finding 模型**：不管来源（Nuclei/Subfinder/爬虫），都转成同一 schema，使报告/计费/去重建立在该模型上。
4. **授权校验放横切层**：所有 tool 调用前拦截，目标不在授权 scope 即拒绝。把法律风险锁死在安全区。
5. **计费粒度 = tool 调用**（MVP 先做配额扣减，后期再加按 finding/资产数）。

---

## 3. MCP Tools 详细设计

### 3.1 统一约定

**授权校验（每个 tool 调用前强制执行）**

```
proof_of_authorization = { scope, token, scope_type }
├── 横切层校验：target ⊆ scope？不在 → NOT_AUTHORIZED（拒绝，不执行）
├── token 在控制台生成，绑定授权 scope
└── 每次调用写审计日志
```

**统一错误模型**

```
{ "error": { "code", "message", "retryable": bool } }

错误码：
├── NOT_AUTHORIZED      目标不在授权 scope（不执行）
├── RATE_LIMITED        配额耗尽 / 限流
├── TOOL_TIMEOUT        工具执行超时（可重试）
├── TOOL_FAILED         底层工具崩溃（可重试，附 stderr 摘要）
├── INVALID_INPUT       参数校验失败（不可重试）
└── COMPLIANCE_BLOCK    触发合规熔断（政府/军工/关键基础设施拒绝列表）
```

**统一 finding 输出模型**

```json
{
  "engagement_id": "eng_abc123",
  "tool": "scan_vulnerabilities",
  "findings": [
    {
      "id": "fnd_001",
      "type": "vulnerability|subdomain|service|exposure|intel|secret_leak",
      "severity": "critical|high|medium|low|info",
      "target": "sub.example.com",
      "title": "CVE-2024-XXXX - Log4Shell on /api",
      "evidence": { "..." : "tool 特定证据字段" },
      "source_tool": "nuclei",
      "raw": { "..." : "原始工具输出（调试用）" },
      "timestamp": "2026-06-16T10:00:00Z"
    }
  ],
  "summary": { "total": 12, "by_severity": {}, "by_type": {} },
  "quota_used": 1
}
```

### 3.2 六个 Tools

#### ① `enumerate_subdomains` — 子域名枚举

| | |
|---|---|
| 输入 | `target_domain`（必填）、`sources`（可选，默认 PD 全集）、`timeout_sec`（默认 120） |
| 底层工具 | subfinder |
| 输出 finding | `type=subdomain`、`severity=info`、`evidence={source, first_seen}` |

#### ② `probe_services` — 存活探测 + 服务识别

| | |
|---|---|
| 输入 | `targets[]`（域名/IP，逐个授权校验）、`ports`（可选）、`threads`（可选） |
| 底层工具 | httpx |
| 输出 finding | `type=service`、`severity=info`、`evidence={port, protocol, service, title, tech_stack, status_code}` |

#### ③ `scan_vulnerabilities` — 漏洞扫描（合规风险最高）

| | |
|---|---|
| 输入 | `targets[]`、`templates`（Nuclei 模板分类）、`severity_filter`、`rate_limit` |
| 底层工具 | nuclei |
| 输出 finding | `type=vulnerability`、`severity=Nuclei 原生`、`evidence={template_id, matched_at, cvss, curl_repro}` |
| **三层合规防护** | 1) 强制 `proof_of_authorization`；2) 内置拒绝列表（.gov/.mil/CII）→ COMPLIANCE_BLOCK；3) 单目标并发上限 + 总速率上限 |

#### ④ `gather_osint` — OSINT 情报收集（B 方向核心）

| | |
|---|---|
| 输入 | `target`（域名或邮箱/人名）、`data_types`（emails/subdomains/breaches/usernames） |
| 底层工具 | theHarvester（MVP 单工具起步） |
| 输出 finding | `type=intel`、`evidence={category, source, ...}` |
| 合规边界 | 只采公开数据，不入侵；breaches 数据来自公开泄露索引（OSINT 非入侵） |

#### ⑤ `scan_secret_leaks` — 凭证泄露监控

| | |
|---|---|
| 输入 | `scope`（域名或 org/repo）、`mode`（MVP 仅 `github`；`public_leaks` 留作后期，见 §7.1 OUT） |
| 底层工具 | gitleaks（MVP 仅此一个），后期接公开泄露库 API（非 MVP） |
| 输出 finding | `type=secret_leak`、`severity=critical/high`、`evidence={repo, file, line, rule_id, secret_type}`（**脱敏存储**，不存明文） |
| 授权逻辑 | MVP `github` 模式扫客户自有仓库（需 GitHub token，客户自备） |
| MVP 边界 | MVP **不实现** `public_leaks` 模式（无公开泄露库 API 依赖）；该模式留作后期 |

#### ⑥ `crawl_target` — SuperSpider 爬虫（差异化壁垒）

| | |
|---|---|
| 输入 | `target`、`depth`、`mode`（static/browser）、`extract`（forms/js_endpoints/emails/comments）、`respect_robots`（默认 true） |
| 底层工具 | pyspider（本仓库，子进程调用） |
| 输出 finding | `type=exposure`、`evidence={url, form_action, js_api, leaked_secret_hint, ...}` |
| 壁垒 | 复用 SuperSpider 的 JS 逆向 + 反爬 + 动态渲染，爬到 SPA 背后的 API/隐藏表单/注释密钥 |

### 3.3 真实调用流程示例

用户在 Claude Code 说"帮我评估一下我公司的资产 acme.com"：

```
agent 自动编排（不靠 run_engagement tool）：
  1. enumerate_subdomains(acme.com)      → 47 个子域名
  2. probe_services([47 子域名])         → 23 个存活
  3. scan_vulnerabilities([23 存活])     → 3 个高危 CVE
  4. crawl_target(acme.com)              → 1 个注释泄露密钥
  5. scan_secret_leaks(acme.com)         → GitHub 2 个泄露凭证
  6. agent 自汇总报告给用户
```

**编排由 agent 完成，MCP 只暴露原子能力。** 这是"不做 run_engagement tool"的依据。

---

## 4. 合规与授权边界（4 道防线）

这是产品能否合法卖钱的命脉。

### 4.1 防线 1：授权登记（无授权，不扫描）

```
授权登记流程（在控制台完成，不经过 agent）：
1. 客户声明资产所有权
2. 所有权验证（三选一，必须通过一项）：
   a. DNS TXT：_scan-verify.example.com TXT="verify=auth_xxx"
   b. 文件验证：example.com/.well-known/scan-auth 放 token
   c. 证书/WHOIS 主体匹配
3. 签署授权同意书（click-through）
4. 生成 authorization_token + scope
```

授权 scope 定义：
- `{ domain: "example.com" }` → 含 `*.example.com`
- `{ ip: "203.0.113.10" }` / `{ cidr: "203.0.113.0/24" }`
- `{ repo: "github.com/acme/*" }`（用于 ⑤）
- `{ email: "person@example.com" }`（用于 ④）

**关键：授权登记走控制台/CLI，不暴露成 MCP tool。** agent 拿到的 token 一定经过所有权验证，杜绝"口头授权扫别人资产"。

### 4.2 防线 2：合规拒绝列表（即使授权也绝不碰）

```yaml
绝对拒绝列表（触发即 COMPLIANCE_BLOCK）：
  - TLD: .gov .mil .gov.cn .edu .gov.uk ...
  - 已知 CII（关键基础设施）域名/IP 清单（定期更新）
  - 内网保留地址（复用 SuperSpider 已有 SSRF 防护）：
    10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.169.254, 127.0.0.0/8
拒绝行为：不执行 + 返回 COMPLIANCE_BLOCK + 审计记录 + 高频触发账户风控
```

### 4.3 防线 3：数据最小化 + 责任边界

```yaml
数据最小化：
  - 只收集授权范围内 finding
  - 凭证泄露（⑤）哈希脱敏：存 "AKIA****XXXX" + 位置，不存明文
  - OSINT（④）只存元数据 + 来源链接
  - 结果默认 90 天后自动清理（可配置）

责任边界（ToS + UI 明示）：
  产品定位：授权资产的自动化安全评估工具（防御性）
  不是：渗透测试服务 / 漏洞利用工具 / 全网测绘平台

  客户责任：确保 scope 确为本人所有；虚假声明后果自负；不得用于未授权目标
  产品责任：维护拒绝列表时效性；不主动入侵/不利用漏洞（Nuclei 只检测）；提供审计日志
```

### 4.4 防线 4：审计与可追溯

```
每次 tool 调用强制记录（追加写，哈希链防篡改）：
{
  timestamp, caller_id, authorization_token,
  tool, target, scope_at_call_time,
  outcome: executed|not_authorized|compliance_block|error,
  findings_count, quota_used, duration_ms
}
用途：客户合规审查、滥用检测、法律举证、计费凭据
存储：SQLite（MVP）→ 追加写 + 哈希链
```

### 4.5 A / B 方向的合规差异

| | A · 防御型 ASM | B · OSINT 情报订阅 |
|---|---|---|
| 授权对象 | 客户自己的资产 | 客户要监控的域名/品牌 |
| 主要 tools | ①②③⑥ | ④⑤ |
| 依赖防线 | 1+2+3+4 全部 | 2+3+4（OSINT 扫公开数据，不需"目标授权"） |

**B 方向合规更宽松**（扫公开数据不需目标授权），使 ④⑤ 商业门槛更低、变现更快。

---

## 5. 技术栈与项目结构

### 5.1 语言选型：Python（单一语言）

- MCP 官方 SDK 有成熟 Python 实现
- 现有最强 runtime 是 pyspider，Python 生态最熟
- subprocess 调二进制语言无关，Python 无劣势
- 鉴权/审计/配额逻辑 Python 迭代最快
- 后期 AI 能力（LLM 解读漏洞/自动报告）Python 生态碾压

**不用 Go/Rust 写 MCP**：那是"被调用的能力"；MCP server 是协调层，迭代速度 > 性能。避免多语言维护成本。

### 5.2 开源工具整合策略：二进制依赖 + 版本锁定

```yaml
核心引擎（Go 二进制）:
  - subfinder   → ①
  - httpx       → ②
  - nuclei      → ③（含 nuclei-templates 子模块）
  - katana      → MVP 不接（⑥ 用自己爬虫）

OSINT 栈（MVP 单工具）:
  - theHarvester → ④

凭证泄露:
  - gitleaks     → ⑤
  - 公开泄露库 API → MVP 不接

封装方式（统一 adapter 模式）:
  每个 tool 一个 adapter，实现 BaseAdapter 接口：
    1. 参数校验 + 授权校验（横切层）
    2. 拼接 CLI + 超时
    3. subprocess 执行
    4. 解析 JSON
    5. 转 Finding
    6. 审计 + 扣配额
    7. 返回

二进制管理:
  - 首次启动 installer 检测 + 下载缺失二进制（校验和验证）
  - versions.py 锁定版本，升级走测试流程
  - nuclei-templates 定期 git pull（MVP 手动触发）
```

### 5.3 项目结构（新增 `secagent/`，不动现有爬虫）

```
爬虫/
├── pyspider/  gospider/  rustspider/  javaspider/   # 现有：保持不动
├── examples/  docs/  tools/                        # 现有
│
├── secagent/                                        # ★ 新增：MCP 产品本体
│   ├── pyproject.toml                               # 独立 Python 包
│   ├── README.md
│   ├── src/secagent/
│   │   ├── server.py                                # MCP server 入口
│   │   ├── tools/                                   # 6 个 tool MCP 定义层
│   │   │   ├── enumerate_subdomains.py              # ①
│   │   │   ├── probe_services.py                    # ②
│   │   │   ├── scan_vulnerabilities.py              # ③
│   │   │   ├── gather_osaint.py                     # ④
│   │   │   ├── scan_secret_leaks.py                 # ⑤
│   │   │   └── crawl_target.py                      # ⑥
│   │   ├── adapters/                                # 开源工具封装层
│   │   │   ├── base.py                              # BaseAdapter 接口
│   │   │   ├── subfinder.py                         # ①
│   │   │   ├── httpx_adapter.py                     # ②
│   │   │   ├── nuclei.py                            # ③
│   │   │   ├── osint/                               # ④
│   │   │   ├── gitleaks.py                          # ⑤
│   │   │   └── superspider.py                       # ⑥
│   │   ├── core/                                    # 横切层（4 道防线）
│   │   │   ├── authz.py                             # 防线 1
│   │   │   ├── blocklist.py                         # 防线 2
│   │   │   ├── audit.py                             # 防线 4
│   │   │   ├── quota.py
│   │   │   ├── compliance.py                        # ③ 三层防护编排
│   │   │   └── finding.py                           # 统一 Finding 模型
│   │   ├── models/
│   │   │   ├── authorization.py
│   │   │   ├── engagement.py
│   │   │   └── report.py
│   │   ├── storage/
│   │   │   ├── sqlite_store.py
│   │   │   ├── migrations/
│   │   │   └── retention.py                         # 防线 3：90 天清理
│   │   ├── binmgmt/
│   │   │   ├── installer.py
│   │   │   ├── versions.py                          # 版本锁定清单
│   │   │   └── launcher.py                          # subprocess+超时+重试
│   │   └── config.py
│   ├── console/                                     # 授权登记（CLI 起步）
│   │   └── README.md
│   ├── tests/
│   │   ├── test_authz.py                            # 授权校验单测（最重要）
│   │   ├── test_blocklist.py
│   │   ├── test_adapters.py                         # mock 二进制
│   │   └── test_tools_e2e.py                        # 打授权测试靶场
│   └── docs/
│       ├── AUTHORIZATION.md
│       ├── COMPLIANCE.md
│       └── DEPLOY.md
```

### 5.4 与 SuperSpider 整合方式

**MVP：子进程调用（方式 A）**。secagent 把 pyspider 当"另一个二进制"调：

```
python -m pyspider crawl --target X --mode browser ...
```

- 优点：解耦，pyspider 改动不影响 secagent；与调 nuclei/subfinder 完全一致
- 后期优化（方式 B 库 import）留作 Team 版

**关键洞察：在 secagent 眼里，SuperSpider 和 Nuclei 没有本质区别——都是"传参 → 跑 → 解析 → 转 Finding"。** 6 个 adapter 实现同一接口，维护成本低。

### 5.5 配置与密钥

```yaml
secagent/config.yaml（不提交 git）:
  database: { path: ./data/secagent.db }
  quota: { default_per_token: 100 }
  compliance:
    blocklist_path: ./data/blocklist.json
    max_concurrent_per_target: 5
    nuclei_rate_limit: 150
  retention: { finding_ttl_days: 90 }
  tools: { binaries_dir: ./bin }

环境变量（不进配置文件）:
  SECAGENT_DB_PATH
  SECAGENT_PUBLIC_LEAK_API_KEY
  SECAGENT_GITHUB_TOKEN
  SECAGENT_OSINT_API_KEYS
```

---

## 6. 变现与商业模式

### 6.1 三个现实

1. **个人开发者不爱为 MCP tool 付费**——同质化多，付费意愿集中在模型/平台。
2. **企业愿为安全付高价**，但门槛是"信任"（授权校验 + 审计 = 进采购清单的门票）。
3. **最赚钱的不是 tool 本身，是数据 + 报告 + 持续监控**（一次性扫描便宜易替代；持续监控订阅贵且粘性高）。

**结论：变现主力是 B2B 企业订阅 + 持续监控，不是向开发者卖 MCP。** MCP 是获客入口和差异化体验。

### 6.2 三条变现线

| 线 | 模式 | 收入 | 特点 |
|---|---|---|---|
| 1 免费获客→企业转化 | MCP 免费试用 → 企业版付费 | 企业年订阅 | 慢但稳，生态杠杆大 |
| 2 OSINT 订阅（B 主力） | 每日跑 ④⑤ + 新 finding 推送 | 月/年订阅 | 粘性极高，监控不能停 |
| 3 API 调用计费（补充） | 按 call/finding 计费 | 按 call | 零散，作补充 |

### 6.3 定价分层

| 档位 | 价格 | 定位 |
|---|---|---|
| Free | $0 | 本地运行，50 次/月，无监控无报告。目的：让人用起来 |
| Pro | $19-29/月 | 托管 MCP，2000 次/月，基础报告，5 资产，邮件告警 |
| Team | $199-499/月 | 持续监控 + 审计导出 + RBAC + Web 控制台。**真正利润在这** |
| Enterprise | 年付面议 | 私有部署 + 定制模板 + SLA + SSO |

**Free/Pro 几乎不指望赚钱，利润在 Team 的持续监控订阅。**

### 6.4 分发策略

- **MCP 目录**：anthropic registry + Smithery + mcp-get（驱动线 1）
- **open-core**：开源 6 tool 的 MCP server，闭源托管/监控/控制台/报告
- **内容营销**：案例博客 + 演示视频 + 安全社区（先诱/Seebug/r/netsec）
- **不碰**：不卖数据给黑灰产、不做未授权代扫、不卖客户数据

### 6.5 MVP 阶段变现目标（务实）

```yaml
MVP（前 3-6 个月）: 不追求收入，追求验证
  - MCP 发布到目录，GitHub 100+ star
  - 3-5 个真实企业 design partner（免费换案例/反馈）
  - 跑通"agent → 扫描 → 报告"链路
  - 验证"持续监控"是真需求
  收入目标: $0

第二阶段（6-12 个月）: 开始收钱
  - 10 个 Team 客户 × $299/月 ≈ $36k/年 ARR
```

**不要在 MVP 阶段纠结定价——先免费让人用，等有人问"能不能付费去限制/加监控"再正式定价。**

---

## 7. MVP 范围与实现路线图

### 7.1 MVP 范围

```yaml
═══════════ IN ═══════════
能力层:
  ✅ 6 个 MCP tools 全部实现
  ✅ 4 道合规防线全部实现
  ✅ 统一 Finding 模型
  ✅ SQLite 存储 + 审计日志

开源工具封装:
  ✅ subfinder(①) httpx(②) nuclei(③) gitleaks(⑤)
  ✅ theHarvester(④，单工具)
  ✅ pyspider(⑥)

交互层:
  ✅ MCP server（stdio + HTTP+SSE）
  ✅ CLI 控制台做授权登记
  ✅ JSON + Markdown 报告

部署:
  ✅ 本地自部署 + install 脚本（下载锁定版本 + 校验和）

═══════════ OUT ═══════════
❌ Web 控制台（CLI 代替）
❌ 持续监控/定时扫描（手动触发）
❌ 邮件/Slack 告警
❌ RBAC / 多用户
❌ 托管服务（只本地）
❌ REST API（MVP 只 MCP）
❌ katana / sherlock / recon-ng / 公开泄露库 API
❌ gospider/rustspider/javaspider 整合（⑥ 只接 pyspider）
❌ 配额计费 / 付费分层 / Stripe
```

**MVP 成功标准**：用户 5 分钟内完成 装好 → 登记授权 → Claude Code 自然语言出报告。

### 7.2 实现路线图（4 个里程碑）

#### M1 · 合规骨架（最先做，命脉）

**目标**：4 道防线独立运行，即使 tools 还没接。
**交付**：
- 授权模型 + scope 校验（`authz.py`）
- 拒绝列表 + COMPLIANCE_BLOCK（`blocklist.py`）
- 审计日志追加写（`audit.py`）
- 统一 Finding 模型（`finding.py`）
- SQLite 存储 + schema 迁移
- 配额扣减骨架（`quota.py`）
- CLI：`secagent authz add/verify/list`

**验证**：单测覆盖每道防线（尤其授权越界 → 拒绝）。
**为什么先做**：没有合规骨架，接 tools 时裸奔，调 nuclei 可能误扫非授权目标。

#### M2 · 第一个 tool 闭环（证明架构）

**目标**：接通 1 个 tool，端到端跑通"调 MCP → 出 finding"。
**交付**：
- `BaseAdapter` 接口 + launcher（subprocess+超时+重试）
- binmgmt：installer + versions 锁定 + 校验和
- `SubfinderAdapter`（①，最简单零风险起步）
- MCP server 骨架，注册 `enumerate_subdomains`
- 端到端测试（打授权测试靶场）

**验证**：Claude Code 里"帮我找 acme.com 子域名"能出结果。
**为什么 ① 起步**：子域名枚举只读公开数据零风险，最适合打通架构。

#### M3 · 补齐其余 5 个 tools（能力完整）

**目标**：6 个 tools 全部可用。
**交付（按风险/复杂度排序）**：
- ② `probe_services`（httpx，读操作）
- ⑥ `crawl_target`（接 pyspider）
- ④ `gather_osint`（theHarvester，读公开数据）
- ⑤ `scan_secret_leaks`（gitleaks，读操作）
- ③ `scan_vulnerabilities`（nuclei，**主动发包，最后做**）

**重点**：③ 接通时，防线 2（拒绝列表）+ 速率保护必须先就位；nuclei `-u` 参数只传白名单后 target。
**验证**：每 tool 有 e2e + adapter 单测（mock 二进制）。
**顺序逻辑**：从低风险读到高风险写，nuclei 压轴。

#### M4 · 体验闭环（能给人用）

**目标**：外部用户能 5 分钟跑通完整链路。
**交付**：
- install 脚本（一键装二进制 + secagent）
- JSON + Markdown 报告生成
- README + AUTHORIZATION.md + demo 视频/动图
- 提交 MCP 目录（anthropic registry + Smithery）
- 1-2 个真实用户跑一遍，收集反馈

**验证**：外部用户独立完成 MVP 成功标准。

### 7.3 风险与缓解

| 风险 | 缓解 |
|---|---|
| 开源工具输出格式漂移 | 版本锁定 + 校验和 + adapter 单测捕获 schema 变化 |
| **nuclei 误扫非授权目标**（最大法律风险） | M1 合规骨架先于 M3；调用前二次校验 target ⊆ scope；`-u` 只传白名单后 target；e2e 专门测越界拒绝 |
| 二进制安装门槛劝退用户 | M4 install 脚本是核心，自动下载 + 校验和一键装；后期托管版兜底 |
| MVP 太大做不完 | 严守 IN/OUT 清单；M1-M4 顺序执行，每里程碑独立可交付；adapter 是复制模式，M3 越做越快 |
| "赚钱"预期错位 | MVP 收入 $0 是设计；M4 后无人付费/做 design partner = 方向要调，不是硬推付费 |

### 7.4 决策记录

| 决策 | 理由 |
|---|---|
| MCP server 用 Python | 最强 runtime 是 pyspider，SDK 成熟，迭代快 |
| 开源工具用二进制依赖 | nuclei 模板 8000+，重写追不上；二进制+版本锁定最优 |
| 爬虫只接 pyspider（MVP） | 四 runtime 都接是过度工程；后期 Team 版再接 |
| MVP 不做 Web 控制台 | CLI 够用，Web 是 Team 版卖点 |
| 不做 run_engagement 编排 tool | agent 比你更会编排，硬塞编排 tool 限制 agent |
| M1 先做合规骨架 | 没合规接 tools 是裸奔，nuclei 误扫是法律灾难 |
| MVP 收入 $0 | 没验证就收费是找死；先 design partner + 口碑 |

---

## 8. 后续阶段（非 MVP，仅记录方向）

- Team 版：Web 控制台 + 持续监控 + 审计导出 + RBAC + REST API
- 扩充工具栈：katana / sherlock / recon-ng / 公开泄露库 API
- 多 runtime：gospider/rustspider/javaspider 接入
- 托管版：免除用户本地装二进制
- AI 能力：LLM 解读漏洞 + 自动生成报告
- 自研 agent 本体（远期）

---

## 附录：术语表

- **ASM / EASM**：Attack Surface Management / External ASM，攻击面管理
- **OSINT**：Open Source Intelligence，公开来源情报
- **MCP**：Model Context Protocol，Anthropic 推出的 agent 工具协议
- **Finding**：扫描发现的一个结果（漏洞/子域名/服务/暴露面/情报/泄露）
- **Engagement**：一次扫描会话，关联多个 finding
- **Authorization scope**：客户授权扫描的目标范围（域名/IP/CIDR/repo/email）
- **CII**：Critical Information Infrastructure，关键信息基础设施
