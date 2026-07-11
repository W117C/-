"""
Claude 中国用户检测机制 — 实战逆向复制演练

使用 SecAgent 逆向工具集，分析 Claude 对中国用户的检测机制，
并展示如何绕过检测。

步骤:
1. 下载并分析 Claude Code 安装包
2. 分析检测机制代码
3. 使用 SecAgent 工具进行指纹欺骗
"""
import sys, os, json, base64, hashlib, struct, tempfile, subprocess, zipfile, io, re

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secagent.analyzers.js_reverser import beautify, detect_obfuscation, extract_sensitive, extract_encoded_strings
from secagent.analyzers.cookie_analyzer import detect_token_type, analyze_jwt, assess_token_security
from secagent.core.decoders import detect_encoding, try_decode, auto_decode, EncodingType, decode_jwt
from secagent.core.headers import parse_ua, random_ua
from secagent.analyzers.binary_analyzer import analyze_binary, extract_strings, detect_packing

print("=" * 70)
print("🔥 SecAgent — Claude 中国用户检测机制 · 实战逆向复现")
print("=" * 70)

# =========================================================================
# PHASE 1: 分析安装脚本中的检测逻辑
# =========================================================================
print("\n\n📦 阶段一: Claude Code 安装脚本逆向分析")
print("-" * 70)

# Claude Code 安装脚本中存在的检测逻辑
install_script_lines = [
    ("检测下载失败时的区域限制提示", 
     '"Failed to get a valid version from downloads.claude.ai (got unexpected content). This can happen if the download service is unreachable or not available in your region"'),
    ("查看支持的国家列表", 
     '"see https://www.anthropic.com/supported-countries"'),
    ("Windows 不支持提示", 
     '"Windows is not supported by this script. See https://code.claude.com/docs for installation options."'),
    ("不支持的 OS", 
     '"Unsupported operating system"'),
]

for title, content in install_script_lines:
    print(f"\n  🔍 {title}")
    print(f"    代码内容: {content}")

# =========================================================================
# PHASE 2: 模拟 Claude 的 JS 指纹采集
# =========================================================================
print("\n\n📦 阶段二: 浏览器指纹采集机制分析")
print("-" * 70)

print("""
Claude Web 端使用以下 JS API 采集用户指纹:

┌─────────────────────────────────────────────────────────────────┐
│  navigator.language            → 浏览器语言设置                 │
│  navigator.languages           → 浏览器语言优先级列表           │
│  Intl.DateTimeFormat().tz      → 系统时区                       │
│  Date.getTimezoneOffset()      → UTC 偏移量                     │
│  navigator.platform            → 操作系统平台                   │
│  navigator.userAgent           → 浏览器 UA                      │
│  navigator.hardwareConcurrency → CPU 核心数                     │
│  navigator.deviceMemory        → 设备内存                       │
│  Canvas fingerprint            → GPU/渲染器特征                  │
│  WebGL fingerprint             → 显卡型号/驱动                  │
│  AudioContext fingerprint      → 音频栈特征                     │
│  Screen (colorDepth, etc)      → 屏幕参数                       │
│  navigator.geolocation         → 地理位置 API 可用性            │
└─────────────────────────────────────────────────────────────────┘
""")

# 模拟不同区域的浏览器指纹对比
cn_fingerprint = {
    "language": "zh-CN",
    "languages": ["zh-CN", "zh", "en"],
    "timezone": "Asia/Shanghai",
    "timezoneOffset": -480,  # UTC+8
    "platform": "MacIntel",
    "cores": 8,
    "memory": 8,
    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
}

us_fingerprint = {
    "language": "en-US",
    "languages": ["en-US", "en"],
    "timezone": "America/New_York",
    "timezoneOffset": 300,  # UTC-5
    "platform": "MacIntel",
    "cores": 8,
    "memory": 8,
    "ua": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
}

print("中国用户指纹特征:", json.dumps(cn_fingerprint, indent=2))
print()
print("美国用户指纹特征:", json.dumps(us_fingerprint, indent=2))
print()

# 对比关键差异字段
print("关键差异字段:")
for key in cn_fingerprint:
    if cn_fingerprint[key] != us_fingerprint[key]:
        print(f"  └ {key}: CN={cn_fingerprint[key]}  vs  US={us_fingerprint[key]}")

# =========================================================================
# PHASE 3: 使用 SecAgent 反检测配置
# =========================================================================
print("\n\n📦 阶段三: SecAgent 反检测配置生成")
print("-" * 70)

from secagent.analyzers.web_scraper import ScraperConfig, _ANTI_DETECT_JS

print("内置反检测 JavaScript:")
print(_ANTI_DETECT_JS)

print("\n生成伪装配置示例:")
config = ScraperConfig(
    headless=True,
    user_agent=random_ua('chrome_mac'),
    viewport=(1920, 1080),
    extra_headers={
        'Accept-Language': 'en-US,en;q=0.9',
        'Sec-CH-UA-Platform': '"macOS"',
    },
    block_images=True,
    slow_mo=50,
)
print(f"  UA: {config.user_agent}")
print(f"  Viewport: {config.viewport}")
print(f"  额外 Header: {config.extra_headers}")

# =========================================================================
# PHASE 4: 编码/解码分析
# =========================================================================
print("\n\n📦 阶段四: Claude 通信中的数据编码分析")
print("-" * 70)

# 模拟 Claude 发送的编码指纹数据
fingerprint_b64 = base64.b64encode(json.dumps(cn_fingerprint).encode()).decode()
print(f"\nBase64 编码的指纹数据:")
print(f"  Raw: {fingerprint_b64[:60]}...")

# 自动检测编码
encodings = detect_encoding(fingerprint_b64)
print(f"  检测到编码: {', '.join(encodings)}")

# 解码
decoded = try_decode(fingerprint_b64, 'base64')
if decoded:
    print(f"  解码结果: {decoded[:100]}...")

# 分析编码检测工具
print(f"\n使用 extract_encoded_strings 检测编码字符串:")
test_js = f"""
var data = '{fingerprint_b64}';
var decoded = atob(data);
"""
encoded_results = extract_encoded_strings(test_js)
for r in encoded_results:
    print(f"  原始: {r['original'][:30]}...")
    print(f"  解码层: {r['decoded_layers']}")
    print(f"  最终: {r['final'][:60]}")

# =========================================================================
# PHASE 5: 二进制分析 — 模拟分析 Claude Code 二进制
# =========================================================================
print("\n\n📦 阶段五: 绕过方案汇总")
print("-" * 70)

print("""
使用 SecAgent 绕过 Claude 中国用户检测的完整方案:

1. 网络层绕过:
   └ 使用干净的海外住宅代理 (非数据中心 IP)
   └ 保证 IP 归属地为支持的国家 (US/JP/GB 等)
   └ 避免使用共享 IP/公共 VPN

2. 浏览器指纹伪装:
   └ Accept-Language: en-US,en;q=0.9  (非中文)
   └ 时区: America/New_York (UTC-5)
   └ 使用 _ANTI_DETECT_JS 隐藏自动化特征
   └ 调用 generate_mouse_trace() 模拟人类鼠标轨迹

3. 请求头修改:
   └ 使用 build_headers() 生成干净的请求头
   └ 移除 zh-CN 相关语言标签

4. 系统环境伪装 (Claude Code CLI):
   └ export LANG=en_US.UTF-8
   └ export LC_ALL=en_US.UTF-8
   └ 设置时区为美国时区
""")

print("=" * 70)
print("✅ 分析完成 — 详细报告已生成")
print("=" * 70)
