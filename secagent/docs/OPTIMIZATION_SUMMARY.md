# SecAgent 优化升级总结

> 2026-06-22 | 基于多轮真实网站实测 + 多智能体交叉审核

---

## 总览

本轮优化覆盖 **6 大能力模块**，经历了 **3 轮多智能体审核**、**2 轮真实网站实测**，累计 **342 个测试**全部通过。

| 模块 | 状态 | 轮次 |
|------|:----:|:----:|
| ① 端口扫描 (`scan_ports`) | ✅ | 1 |
| ② 目录模糊测试 (`discover_paths`) | ✅ | 1 |
| ③ 被动侦察增强 (`passive_recon`) | ✅ | 1 |
| ④ WAF/CDN 检测 | ✅ | 2 |
| ⑤ 结果差异对比 (`findings diff`) | ✅ | 2 |
| ⑥ 技术栈感知路径模糊测试 | ✅ | 2 |
| ⑦ 健康诊断 (`check_health`) | ✅ | 2 |
| ⑧ IP 匿名化系统 (ProxyManager) | ✅ | 3 |

---

## 轮次 1：漏洞发现能力强化

### 新增工具

#### `scan_ports` (naabu 端口扫描)

| 特性 | 说明 |
|------|------|
| 扫描模式 | connect（默认）/ syn |
| 端口范围 | 自定义，默认 `80,443,8080-8090,8443` |
| 速率控制 | 上限 2000 pps |
| 输出 | Type: `open_port`, Severity: `info` |

真实测试结果：httpbin.org 发现 80/443/8080 开放，识别 gunicorn/jQuery/React 等技术栈。

#### `discover_paths` (ffuf 目录模糊测试)

| 特性 | 说明 |
|------|------|
| 内置字典 | ~1200 条路径，`importlib.resources` 嵌入包 |
| 通用字典 | 可选 L2 (5000条) / L3 (SecLists) |
| 速率限制 | 默认 100/s，上限 500/s |
| 递归深度 | 上限 3 |
| 严重度分类 | 自动按路径模式分级 (critical/high/medium/low) |

#### `passive_recon` (被动侦察增强)

| 数据源 | 需要 API Key | 降级行为 |
|--------|:----------:|---------|
| crt.sh | 否 | ✅ 静默降级 |
| SecurityTrails | 可选 (`SECAGENT_SECURITYTRAILS_KEY`) | ✅ 静默降级 |
| Shodan | 可选 (`SECAGENT_SHODAN_KEY`) | ✅ 静默降级 |

真实测试结果：httpbin.org 通过 crt.sh 发现 5 个子域名 (`eu`, `www`, `now`, `staging`, `test`)。

### 安全加固

- **DNS 解析 IP 检查**：`gate.check()` 解析目标 hostname 并检查解析后的 IP 是否在禁止列表
- **速率限制继承**：所有新增工具继承 nuclei 的速率上限模式
- **词条上限**：ffuf 默认词条上限 20000

---

## 轮次 2：智能增强 + 诊断

### WAF/CDN 检测

| 检测目标 | 数量 |
|---------|:----:|
| CDN + WAF | Cloudflare, AWS CloudFront, Akamai, Fastly |
| WAF | Imperva/Incapsula, Sucuri, ModSecurity, F5 BIG-IP, FortiWeb, Radware |
| CDN | StackPath, KeyCDN, BunnyCDN |
| 合计 | **15+** |

自动集成到 `probe_services` 的 evidence 中，字段名为 `waf`。

### 结果差异对比

```bash
secagent findings diff --old-engagement eng_xxx --new-engagement eng_yyy
secagent findings diff --old-hours 72 --new-hours 24
secagent findings diff --list-engagements
```

对比两轮扫描的发现，自动标记 🆕NEW / ✅RESOLVED / 不变。

### 技术栈感知路径模糊测试

`core/tech_paths.py` 包含 20+ 技术栈的针对性路径：

```
WordPress → wp-admin, wp-content, xmlrpc.php, wp-json/...
Spring    → actuator/health, actuator/env, swagger-ui/...
nginx     → nginx-status, health
IIS       → aspnet_client/, web.config, appsettings.json
GraphQL   → graphql, graphiql, api/graphql
...
```

链式调用中自动从 `probe_services` 结果提取 tech_stack 传递给 `discover_paths`。

### check_health 诊断工具

注册到 MCP 的同步工具，无需 auth token：

```json
{
  "status": "ok",
  "db": {"tokens": 6, "findings": 169},
  "binaries": {"nuclei": {"found": true, "version": "v3.3.5"}, ...},
  "proxy": {"enabled": false}
}
```

---

## 轮次 3：IP 匿名化系统

...

## 轮次 4：PySocks SOCKS5 修复 + 验证

### 修复内容

`ProxyManager.socks_context()` 改用 `socket.create_connection` 替换方案（而非全局 `socket.socket` 替换），解决 PySocks 与 urllib 的兼容性问题。

### 真实测试验证

| 测试 | 结果 |
|------|------|
| 真实 IP (无代理) | `13.215.159.215` |
| 通过 Tor SOCKS5 | `2406:da18:16e:cb00:10c2:6292:d554:4cf4` ✅ |
| 上下文退出后 | 恢复为 `13.215.159.215` ✅ |
| urllib HTTP + SOCKS5 | ✅ 通过 |
| urllib HTTPS + SOCKS5 | ✅ 通过 |

### 支持的代理场景

| 代理类型 | Python 工具 (simple_crawler/passive_recon) | CLI 工具 (nuclei/httpx/ffuf) |
|---------|:----------------------------------------:|:---------------------------:|
| HTTP/HTTPS | `ProxyHandler` ✅ | `-proxy` flag ✅ |
| SOCKS5 | `socks_context()` ✅ | `-proxy` flag ✅ |

### 架构

```
ProxyManager (core/proxy.py)
  ├─ ProxyPool: 线程安全代理池，round_robin/random 策略
  ├─ 健康追踪：alive/dead 状态管理
  └─ get_proxy(target) → proxy_url

Launcher (binmgmt/launcher.py)
  ├─ __init__(proxy_manager) → 构造时注入
  ├─ _inject_proxy(cmd, tool_name, target)
  ├─ nuclei/httpx/naabu/subfinder → 自动加 -proxy flag
  ├─ ffuf → 自动加 -x flag
  └─ gitleaks/theHarvester → 自动设 ALL_PROXY env

Python urllib 工具
  ├─ simple_crawler → ProxyHandler
  └─ passive_recon → ProxyHandler
```

### 代理配置方式

```yaml
# config.yaml
proxy:
  enabled: true
  strategy: round_robin
  pool:
    - socks5://proxy1:1080
    - socks5://proxy2:1080
```

或环境变量：
```bash
ALL_PROXY=socks5://127.0.0.1:9050
```

### 真实测试验证

| 测试 | 结果 |
|------|------|
| 真实 IP (无代理) | `13.215.159.215` |
| 通过 Tor 代理 | `193.189.100.204` (不同 IP) |
| launcher 自动注入 `-proxy` flag | ✅ 验证通过 |
| gitleaks 环境变量代理 | ✅ 验证通过 |
| Config 加载 (yaml + env) | ✅ 验证通过 |

---

## 测试统计

| 阶段 | 测试数 | 通过率 |
|:----|:------:|:------:|
| 优化前基线 | 226 | 100% |
| 第 1 轮强化后 | 299 | 100% |
| 第 2 轮强化后 | 307 | 100% |
| 第 3 轮代理后 | **342** | **100%** |

---

## 实战发现问题的修复清单

| # | 问题 | 发现方式 | 修复 |
|---|------|---------|------|
| 1 | ffuf `-max-time` → `-maxtime` flag 错误 | 🌐 真实测试 | `ffuf.py` |
| 2 | naabu IPv4/IPv6 端口重复 | 🌐 真实测试 | `naabu.py` 去重 |
| 3 | 链式调用作用域不匹配 (IP vs 域名) | 🌐 真实测试 | `httpx_adapter.py` + `attack_surface_scan.py` |
| 4 | proxychains4 macOS SIP 不兼容 | 🤖 智能体审核 | 改用原生 `-proxy` flag |
| 5 | Python urllib 不支持 SOCKS5 | 🤖 智能体审核 | 记录为已知限制 |
| 6 | 被动侦察空列表被当作"未指定" | 🔬 单元测试 | `passive_recon.py` sources 判断 |
| 7 | WAF 检测重复 (Cloudflare 多条匹配) | 🔬 单元测试 | 去重逻辑修正 |

---

## 已知限制（后续迭代）

| 限制 | 说明 |
|------|------|
### Python urllib 不支持 SOCKS5 | 通过 PySocks 修复 | 轮次 3 已验证
| Python urllib 不支持 SOCKS5 | `ProxyHandler` 仅支持 HTTP/HTTPS。通过 PySocks 的 `socket.create_connection` 替换方案修复，已验证 Tor SOCKS5 正常工作 | ✅ 已修复（轮次 4） |
| 跨工具速率聚合 | 暂无每令牌滑动窗口限流 |
| CVE 关联 | 移到报告层，暂未实现 |
| Web 截图 | 需要 Chromium，暂未集成 |
| 自动化 CI 集成测试 | 对已知靶场进行自动化链式测试 |

---

## 文件变更总结

```
新增 18 个文件，修改 12 个文件
总计约 ~2500 行净增代码
```

| 目录 | 新增 | 修改 |
|------|:----:|:----:|
| `core/` | proxy.py, waf_detect.py, tech_paths.py | gate.py, finding.py |
| `adapters/` | naabu.py, ffuf.py | httpx_adapter.py, simple_crawler.py |
| `tools/` | scan_ports.py, discover_paths.py, passive_recon.py, check_health.py | attack_surface_scan.py |
| `binmgmt/` | — | launcher.py, versions.py, installer.py |
| `server/` | — | tools_registry.py, app.py |
| `cli/` | — | findings.py |
| `wordlists/` | paths_builtin.txt | — |
| `tests/` | 8 个新测试文件 | 3 个更新 |
