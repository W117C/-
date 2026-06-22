# SecAgent 优化方案

> 基于第一次实操体验的诊断，按优先级排序。

---

## P0: 慢工具异步化——MCP 超时问题

**根因**: `probe_services`（httpx）和 `gather_osint`（theHarvester）执行时间 30s~数分钟，MCP 客户端 60s 同步超时后直接丢响应。在 6 个工具中这两个当前**不可用**。

### 方案: 提交-轮询模式 (async poll)

新增两个 MCP 工具 `submit_scan` / `poll_result`：

```
agent                    MCP server                  adapter (httpx/nuclei/theHarvester)
  |--- submit_scan ------->|                              |
  |     {tool, params}     |-- gate.check()               |
  |<-- {job_id, status} ---|                              |
  |                         |-- spawn subprocess --------->|
  |                         |                              |--- running...
  |                         |                              |
  |--- poll_result ------->|                              |
  |     {job_id}           |-- read stdout so far          |
  |<-- {status, partial} --|                              |
  |                         |                              |
  |--- poll_result ------->|                              |
  |     {job_id}           |-- subprocess exited           |
  |<-- {status:done, fnds}-|                              |
```

**具体改动**:

| 层 | 文件 | 改动 |
|----|------|------|
| MCP 工具 | `tools_registry.py` | 新增 `submit_scan` / `poll_result` 两个 ToolDefinition |
| Server | `app.py` | `call_tool()` 路由到新 handler |
| 调度器 | 新建 `core/scheduler.py` | `JobManager`：spawn 子进程 → 管 stdout buffer → 收结果 |
| 存储 | `storage/sqlite_store.py` 迁移 002 | `jobs` 表: id/token/tool/params/status(stdout_buffer)/findings_json/created_at |
| CLI 查询 | `cli/findings.py` | `secagent jobs list` / `secagent jobs show <id>` |

**接口设计**:

```json
// submit_scan 入参
{
  "tool": "probe_services",          // 3个慢工具: probe_services | gather_osint | scan_vulnerabilities
  "params": { "targets": [...], ... },
  "authz_token": "auth_xxx",
  "caller_id": "string"
}

// submit_scan 出参
{
  "job_id": "job_abc123",
  "status": "running",
  "tool": "probe_services"
}

// poll_result 入参
{ "job_id": "job_abc123" }

// poll_result 出参（运行中）
{ "job_id": "job_abc123", "status": "running", "tool": "probe_services" }

// poll_result 出参（完成）
{
  "job_id": "job_abc123",
  "status": "done",
  "tool": "probe_services",
  "engagement_id": "eng_xxx",
  "findings": [...],
  "summary": { "total": N, ... }
}
```

**agent 使用方式**: 
```
1. submit_scan(probe_services, 22 targets)
2. poll_result(job_id) → still running
3. poll_result(job_id) → done, 返回 findings
```

**耗时估计**: 3 天（JobManager + 2 个 MCP handler + CLI + 测试）

---

## P1: 结果持久化——scan 历史回顾

**根因**: 扫描结果只存在于 MCP 响应中，对话关闭就没了。没有一个 `secagent findings list` 来回顾历史发现。

### 改动

| 文件 | 改动 |
|------|------|
| `storage/sqlite_store.py` 迁移 003 | 新增 `findings` 表（id/engagement/tool/target/severity/type/title/evidence_json/timestamp）|
| `core/gate.py` | `commit_findings()` 中额外写入 `findings` 表 |
| `cli/findings.py` | 新增 `secagent findings` 子命令组 |

**CLI 接口**:

```bash
secagent findings list                     # 最近 50 条
secagent findings list --tool probe_services
secagent findings list --severity high
secagent findings list --target lixiang.com --limit 20
```

**耗时**: 0.5 天

---

## P2: `secagent report` 命令

**根因**: `render_markdown()` 代码已写好，但只能通过 import 调用，没有 CLI 入口。

### 改动

```bash
secagent report --tool probe_services --output scan.md
secagent report --engagement eng_abc123 --output /tmp/report.md
secagent report --all --output full-report.md
```

关联 P1 的 `findings` 表，自动从 SQLite 取数据渲染。

**新建文件**: `cli/report.py`（~40 行，thin wrapper）

**耗时**: 0.3 天

---

## P3: 授权体验优化

**根因**: 单用户场景下 `authz add + verify` 两步有点繁琐，且 verify 不实际检查，徒有仪式感。

### 改动

| 改动 | 说明 |
|------|------|
| `secagent authz quick --domain x.com` | 一步完成 add + verify，CLI 提示法律责任 |
| `secagent authz add --verified` | add 时加 flag 直接标记 verified |
| `~/.reasonix/secagent.yaml` | 支持全局默认配置，免去每次设环境变量 |

**耗时**: 0.5 天

---

## P4: 工具维度细化

**根因**: `probe_services` 要求至少一个 target 且同步等待全部完成，单 target 超时时其他 target 的结果也拿不到。

### 改动

- `enumerate_subdomains` 返回结果时自动插入 `probe_services` 的 target 列表（agent 无需手动解析再传）
- `probe_services` 支持 `max_concurrency` 参数
- 每个 adapter 加行级超时: httpx 默认 30s/target，theHarvester 默认 90s

**耗时**: 0.5 天

---

## P5: 增加 `check_health` 工具

**根因**: MCP 配置排查花了太多轮。如果启动时就有一个快速健康检查工具，能在 1 轮内定位到权限/环境/二进制问题。

```json
// check_health 出参
{
  "status": "ok" | "degraded",
  "python": "3.9.6",
  "db": "connected (2 tokens, 0 findings)",
  "binaries": {
    "subfinder": { "found": true, "version": "v2.6.7" },
    "httpx": { "found": true, "version": "v1.6.9" },
    "nuclei": { "found": false, "error": "binary not found at ./bin/nuclei" },
    "gitleaks": { "found": true, "version": "v8.18.4" }
  },
  "mcp": { "tools": 6, "transport": "stdio" }
}
```

**耗时**: 0.3 天

---

## 优先级汇总

| 优先级 | 改动 | 耗时 | 解决什么 |
|--------|------|------|---------|
| **P0** | 慢工具异步化 (submit/poll) | 3d | probe_services/gather_osint/scan_vulnerabilities 不可用 |
| **P1** | findings 持久化 + CLI 查询 | 0.5d | 结果关对话就丢 |
| **P2** | `secagent report` 命令 | 0.3d | 报告生成要写 Python |
| **P3** | authz quick/--verified | 0.5d | 单用户场景太啰嗦 |
| **P4** | probe 单目标拆解 | 0.5d | 一个 target 挂全挂 |
| **P5** | `check_health` 工具 | 0.3d | MCP 排查成本高 |

**总工期: ~5 天**，建议按 P0→P1→P2 顺序切，每次切完可验证。

---

## 不做的事情

- **Web console**: MVP 不碰 UI，维持 CLI + MCP
- **REST API**: 继续 stdio only
- **多用户/RBAC**: 当前单用户够用
- **定时扫描**: 手动触发足够
- **通知/Slack 告警**: 无需求
