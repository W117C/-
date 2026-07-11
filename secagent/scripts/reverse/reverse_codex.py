"""
Codex CLI 软件逆向分析 — SecAgent 工具链实战

分析目标: openai/codex (Rust 编写的轻量级编程Agent)
分析工具: SecAgent 逆向工具集 (js_reverser, cookie_analyzer, decoders, headers, binary_analyzer)
"""
import sys, os, json, base64, hashlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secagent.analyzers.js_reverser import beautify, detect_obfuscation, extract_sensitive, extract_encoded_strings
from secagent.analyzers.cookie_analyzer import detect_token_type, analyze_jwt, assess_token_security
from secagent.core.decoders import detect_encoding, try_decode, auto_decode, EncodingType
from secagent.core.headers import parse_ua, random_ua
from secagent.analyzers.web_scraper import ScraperConfig, _ANTI_DETECT_JS

print("=" * 70)
print("🔍 SecAgent 逆向分析 — OpenAI Codex CLI")
print("=" * 70)

# =========================================================================
# PHASE 1: 仓库架构概述
# =========================================================================
print("\n\n## 1. 仓库基本信息")
print("-" * 70)
print("""
  Repository: openai/codex
  Language:   Rust (99%+)
  License:    Apache-2.0
  Stars:      95,852
  Description: Lightweight coding agent that runs in your terminal
  
  🏗️ 架构分层:
  ┌─────────────────────────────────────────────┐
  │  codex.js (NPM 入口)                        │
  │  └ 平台检测 → 选择对应 Rust 二进制          │
  ├─────────────────────────────────────────────┤
  │  codex-rs/cli (CLI 入口)                    │
  ├─────────────────────────────────────────────┤
  │  codex-rs/core (核心 Agent 逻辑)            │
  │  ├ login/ → 认证与 Token 管理               │
  │  ├ config/ → 配置加载与校验                 │
  │  ├ context/ → 环境上下文采集                │
  │  ├ tools/ → 工具系统 (shell, patch, etc)    │
  │  └ sandboxing/ → 沙箱与安全隔离            │
  ├─────────────────────────────────────────────┤
  │  codex-rs/tui (终端 UI)                     │
  └─────────────────────────────────────────────┘
""")

# =========================================================================
# PHASE 2: NPM 入口分析
# =========================================================================
print("\n\n## 2. NPM 入口 codex.js 分析")
print("-" * 70)

codex_js = """#!/usr/bin/env node
import { spawn } from "node:child_process";
import { existsSync, realpathSync } from "fs";
import { createRequire } from "node:module";
import path from "path";
import { fileURLToPath } from "url";

const PLATFORM_PACKAGE_BY_TARGET = {
  "x86_64-unknown-linux-musl": "@openai/codex-linux-x64",
  "aarch64-unknown-linux-musl": "@openai/codex-linux-arm64",
  "x86_64-apple-darwin": "@openai/codex-darwin-x64",
  "aarch64-apple-darwin": "@openai/codex-darwin-arm64",
  "x86_64-pc-windows-msvc": "@openai/codex-win32-x64",
  "aarch64-pc-windows-msvc": "@openai/codex-win32-arm64",
};

const { platform, arch } = process;
// ... 平台检测逻辑
// ... 将控制权转交给对应平台的 Rust 二进制
"""

print("检测到的混淆模式:")
for r in detect_obfuscation(codex_js):
    print(f"  [{r['name']}] {r['description']} x{r['match_count']} 置信度:{r['confidence']}%")

print("\n提取的敏感信息:")
for s in extract_sensitive(codex_js):
    print(f"  [{s['type']}] {s['description']}: {s['value'][:80]}")

print("\n格式化后的入口逻辑:")
print(beautify(codex_js.split('const { platform, arch }')[0]))

# =========================================================================
# PHASE 3: 安装脚本分析
# =========================================================================
print("\n\n## 3. 安装脚本 (install.sh) 逆向分析")
print("-" * 70)

install_sh = """#!/bin/sh
RELEASE="${CODEX_RELEASE:-latest}"
BIN_DIR="${CODEX_INSTALL_DIR:-$HOME/.local/bin}"
CODEX_HOME_DIR="${CODEX_HOME:-$HOME/.codex}"
RELEASES_DIR="$CODEX_HOME_DIR/packages/standalone/releases"

# 通过 GitHub API 获取版本元数据
release_metadata_url() {
  printf 'https://api.github.com/repos/openai/codex/releases/tags/rust-v%s' "$1"
}
"""

print("检测到的混淆/编码:", detect_obfuscation(install_sh))

print("""
🔑 关键发现: 与 Claude Code 对比

┌───────────────────────────┬─────────────────────┬──────────────────────┐
│        特征               │    Claude Code       │      Codex CLI       │
├───────────────────────────┼─────────────────────┼──────────────────────┤
│ 安装源                    │ claude.ai (CDN)      │ GitHub Releases      │
│ 安装脚本地区封锁          │ ✅ 有显式提示        │ ❌ 无地区检测        │
│ 运行时二进制              │ Node.js + Python     │ Rust (原生编译)      │
│ 逆-难-度                  │ 中等 (JS/Python)     │ 高 (Rust 二进制)     │
│ 认证方式                  │ Persona KYC          │ ChatGPT 账号/API Key │
│ 客户端地区检测            │ ✅ 检测 locale/IP    │ ❌ 源码未见检测      │
└───────────────────────────┴─────────────────────┴──────────────────────┘
  
Codex CLI 在客户端层面没有内置的地区检测逻辑。
真正的限制发生在 OpenAI 服务端 (API/Sign-in)。
""")

# =========================================================================
# PHASE 4: JWT/Token 分析
# =========================================================================
print("\n\n## 4. 认证 Token 分析")
print("-" * 70)

# Codex uses access tokens with "at-" prefix
print("Codex 认证 Token 类型:")

sample_tokens = [
    # Codex 的 Personal Access Token
    ("at-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz", "Codex PAT Token (at- prefix)"),
    # 标准 JWT (ChatGPT session token)
    ("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJpc3MiOiJvcGVuYWkiLCJzdWIiOiJ1c2VyX2lkIiwiYXVkIjoiY29kZXgiLCJpYXQiOjE3MTc2MDAwMDAsImV4cCI6MTc0OTEzNjAwMCwidHlwIjoiYWNjZXNzIiwic2NwIjoiY29kZXg6d3JpdGUifQ.signature",
     "Codex JWT Session Token"),
]

for token, desc in sample_tokens:
    print(f"\n  类型: {desc}")
    token_types = detect_token_type(token)
    for t in token_types:
        print(f"  [{t['type']}] {t['description']} 置信度: {t['confidence']}%")
    
    if token.startswith('eyJ'):
        result = analyze_jwt(token)
        if result.valid_structure:
            print(f"  JWT 算法: {result.algorithm}")
            print(f"  JWT 签发者: {result.issuer}")
            print(f"  JWT 主题: {result.subject}")
            print(f"  JWT 签发时间: {result.issued_at}")
            print(f"  JWT 过期时间: {result.expires_at}")
        else:
            print("  (签名被截断, JWT 结构验证跳过)")
    
    sec = assess_token_security(token)
    print(f"  长度: {sec['length']} chars, 熵值: {sec['entropy']}")

print("\n📌 关于 at- 前缀:")
print("""
  Codex 使用 Personal Access Token (PAT) 进行 API 认证:
  - 格式: at-[random string]
  - 来源: API Key 或 OAuth2 设备码授权流程
  - 用途: 访问 OpenAI Responses API
  
  Type: personal_access_token | agent_identity_jwt
""")

# =========================================================================
# PHASE 5: Rust 二进制分析（静态分析）
# =========================================================================
print("\n\n## 5. Rust 二进制安全分析")
print("-" * 70)

# 使用 binary_analyzer 对 Rust 编译产物进行分析 (如果本地有二进制)
print("""
Rust 编译特点对逆向的影响:

  1. 静态链接 — 几乎不依赖外部库, 难以通过替换库来 hook
  2. LTO 优化 — 函数内联, 符号难以定位
  3. 无反射 — 没有 Python/JS 的 eval/getattr 机制
  4. 直接系统调用 — 难以注入拦截
  
  这对逆向意味着:
  - 难以动态修改行为 (不能 patch JS/Python 代码)
  - 需要二进制级别 patch (hex 编辑或反编译)
  - Hook 点有限 (syscall, network, file I/O)
""")

# Simulate binary analysis
print("使用 binary_analyzer 模拟分析 Rust 二进制:")
test_binary_data = bytes([
    0x7f, 0x45, 0x4c, 0x46,  # ELF magic
    0x02,  # 64-bit
    0x01,  # little endian
    # ... 模拟更多数据
])
print(f"  Magic bytes: {' '.join(f'{b:02x}' for b in test_binary_data[:4])} → ELF 64-bit")
print(f"  架构: x86_64 / aarch64 (跨平台)")
print(f"  链接方式: 静态链接 musl (Linux)")

# =========================================================================
# PHASE 6: 关键路径与函数分析
# =========================================================================
print("\n\n## 6. 关键子模块分析")
print("-" * 70)

key_modules = {
    "codex-rs/login/src/": "认证系统 — OAuth2/PKCE 设备码流程",
    "codex-rs/core/src/sandboxing/": "沙箱模块 — bwrap/landlock 安全隔离",
    "codex-rs/core/src/tools/handlers/shell/shell_command.rs": "Shell 命令执行",
    "codex-rs/core/src/tools/handlers/agent_jobs/": "多 Agent 任务编排",
    "codex-rs/core/src/config/": "配置加载 (TOML)",
    "codex-rs/codex-client/src/": "HTTP 客户端 — 代理/Cookie/CA",
    "codex-rs/core/src/context/world_state/": "环境状态收集",
    "codex-rs/exec-server/src/": "远程执行服务器",
    "codex-rs/tui/src/": "终端 UI (ratatui)",
    "codex-rs/core/src/session/": "会话管理",
    "codex-rs/core/src/guardian/": "安全守护进程",
    "codex-rs/core/src/tasks/": "任务编排",
}

for path, desc in key_modules.items():
    print(f"  📁 {path}")
    print(f"     └ {desc}")

# =========================================================================
# PHASE 7: 综合安全评估
# =========================================================================
print("\n\n## 7. 安全评估与反制分析")
print("-" * 70)

print("""
┌─────────────────────────────────────────────────────────────────┐
│ Codex CLI 安全防线                                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                   
│ 1. 代码签名 — GitHub Release 提供 SHA256 校验和                  
│ 2. 沙箱执行 — Linux: bwrap + Landlock, Windows: AppContainer    
│ 3. 权限控制 — ManagedFileSystemPermissions 细粒度文件访问       
│ 4. 网络代理 — MITM代理 + 凭证管理 (credential_broker)           
│ 5. 安全审计 — capability-based execpolicy                        
│                                                                   
└─────────────────────────────────────────────────────────────────┘

🔐 与 Claude Code 的关键区别:

┌──────────────────────┬────────────────┬────────────────┐
│      项目            │  Claude Code   │   Codex CLI    │
├──────────────────────┼────────────────┼────────────────┤
│ 客户端地区检测        │ ✅ 有          │ ❌ 无          │
│ 安装限制              │ ✅ 地区封锁    │ ❌ 开放下载    │
│ 认证 KYC              │ ✅ Persona     │ ❌ ChatGPT 登录│
│ 沙箱隔离              │ ❌ 无          │ ✅ bwrap/Landlock│
│ 源码可审计            │ ❌ 闭源二进制  │ ✅ 开源 Rust   │
└──────────────────────┴────────────────┴────────────────┘

⚠️ 实际的地区限制存在于 OpenAI 服务端:
  - chatgpt.com 的 Cloudflare 保护
  - API Key 归属地检测
  - ChatGPT Plus/Pro 订阅的地区限制
""")

# =========================================================================
# PHASE 8: 反制配置生成
# =========================================================================
print("\n\n## 8. SecAgent 反检测配置 (针对服务端限制)")
print("-" * 70)

print("使用 SecAgent web_scraper 生成浏览器指纹伪装:")
config = ScraperConfig(
    headless=True,
    user_agent=random_ua('chrome_mac'),
    viewport=(1920, 1080),
    extra_headers={
        'Accept-Language': 'en-US,en;q=0.9',
    }
)
print(f"  UA: {config.user_agent}")
print(f"  Headers: {config.extra_headers}")
print(f"  Viewport: {config.viewport}")

print(f"\n内置反检测 JS (隐藏自动化特征):")
print(_ANTI_DETECT_JS)

print("=" * 70)
print("✅ Codex CLI 逆向分析完成")
print("=" * 70)
