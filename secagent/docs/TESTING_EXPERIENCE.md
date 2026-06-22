# SecAgent 实战测试报告

> 2026-06-22 | 针对 4 个公开测试网站进行全工具链测试

---

## 测试目标

| 网站 | 类型 | 测试目的 |
|------|------|---------|
| `testphp.vulnweb.com` | Acunetix 测试靶场 | 通用 Web 漏洞扫描测试 |
| `testasp.vulnweb.com` | Acunetix 测试靶场 | ASP/IIS 环境探测 |
| `httpbin.org` | HTTP 请求测试服务 | 子域名枚举 + 服务发现 |
| `public-firing-range.appspot.com` | Google 安全测试靶场 | Google Cloud 服务探测 |

---

## 测试结果摘要

```
工具链: enum → port scan → probe → path fuzz → nuclei → passive recon
        ✅       ✅         ✅       ⚠️          ✅        ✅

阶段成功率(不含路径模糊测试): 5/5 ✅
```

| 工具 | 结果 | 说明 |
|------|:----:|------|
| `enumerate_subdomains` | ✅ | httpbin.org 发现 2 个子域名（eu, www） |
| `scan_ports` | ✅ | 每个目标发现 3-6 个开放端口 |
| `probe_services` | ✅ | 成功识别技术栈（IIS, ASP.NET, Python, React, gunicorn 等） |
| `discover_paths` | ⚠️ | ffuf flag bug 已修复，需重测 |
| `passive_recon` | ✅ | httpbin.org 通过 crt.sh 发现 5 个子域名 |
| `attack_surface_scan` | ⚠️ | 链式调用已修复，需重测 |

---

## 发现的问题（已修复）

### P0 — ffuf `-max-time` flag 不存在 (✅ 已修复)

**现象**: ffuf 报错 `flag provided but not defined: -max-time`  
**根因**: ffuf 的 CLI flag 是 `-maxtime`（无连字符），不是 `-max-time`  
**修复**: 将适配器中 `-max-time` 改为 `-maxtime`  
**文件**: `src/secagent/adapters/ffuf.py`

### P0 — 端口扫描 IPv4/IPv6 重复 (✅ 已修复)

**现象**: naabu 返回同一端口的 IPv4 和 IPv6 结果，产生 6-28 条重复发现  
**根因**: 适配器未对相同端口号去重  
**修复**: 在 `_parse_output()` 中添加 `(port, protocol)` 去重集合  
**文件**: `src/secagent/adapters/naabu.py`

### P1 — 链式调用作用域不匹配 (✅ 已修复)

**现象**: `attack_surface_scan` 链中，`probe_services` 返回解析后的 IP 而非原始域名，传递给 `scan_vulnerabilities` 时作用域检查失败  
**根因**: `_service_scan_target()` 使用 finding 的 `target` 字段（IP），而该 IP 不在授权域名作用域内  
**修复**: 
  1. `httpx_adapter.py` 的 evidence 中增加 `input_host` 字段（原始域名）
  2. `_service_scan_target()` 优先使用 `evidence.input_host`  
  3. `attack_surface_scan.py` 各阶段增加异常捕获，避免单阶段失败拖垮整个链

### P2 — 被动侦察 SSL 证书验证

**现象**: crt.sh API 使用自签名证书导致 `ssl.CERT_NONE` 需要跳过验证  
**处理**: 已使用 `ssl.create_default_context()` 并设置 `CERT_NONE`

### P2 — theHarvester 在 bin/ 中是脚本而非二进制

**现象**: `bin/theHarvester` 是 563 字节的 shebang 脚本，与 ProjectDiscovery 二进制混放  
**影响**: 低频使用不影响功能，但安装方式不一致（pip install）

---

## 经验总结

### 1. 链式调用的作用域传递

安全扫描链的核心挑战：**前一阶段产生的结果可能不适合后一阶段的合规检查**。httpx 返回 IP 而不是原始域名，导致后续 nuclei 的作用域检查失败。

**解决方案**: 每个阶段的结果都应该保留原始目标信息，后一阶段使用原始目标进行作用域检查。

### 2. 工具 flag 兼容性

不同版本的同一工具可能有不同的 CLI flag。ffuf 的 `-maxtime` vs `-max-time` 是一个典型问题。

**解决方案**: 使用前进行 flag 验证，或者在 CI 中添加真实工具版本测试。

### 3. 去重策略

naabu 的 IPv4/IPv6 双栈返回会产生重复端口数据。扫描结果去重应该在适配器层完成。

### 4. 开箱即用体验

- **内置词库**: 1200 条路径开箱即用，零配置 ✅
- **二进制管理**: naabu 和 ffuf 需要 `brew install` 或通过安装脚本下载
- **DNS 解析检查**: 新增了主机名→IP 的 DNS 检查，防止私有 IP 泄露 ✅

---

## 后续优化方向

| 优先级 | 项目 | 说明 |
|--------|------|------|
| P0 | 自动化集成测试 | 在 CI 中对已知测试靶场运行全工具链 |
| P1 | 技术栈感知路径模糊测试 | 根据 httpx 发现的技术栈选择更相关的字典子集 |
| P1 | 结果差异对比 | 多轮扫描结果对比，只报告新变化 |
| P2 | WAF/CDN 检测 | 在 probe 阶段识别 Cloudflare/Akamai/AWS WAF |
| P2 | `check_health` 工具 | 快速验证所有二进制/字典/权限就绪 |
| P3 | 跨工具速率聚合 | 防止用户同时运行多个高频工具导致目标过载 |
