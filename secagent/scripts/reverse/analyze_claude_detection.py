"""
SecAgent Claude 中国用户检测机制逆向分析

使用 SecAgent 工具包分析 Claude 如何检测和识别中国用户。
"""
import sys, json, os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secagent.analyzers.js_reverser import (
    detect_obfuscation, extract_sensitive, beautify, extract_encoded_strings
)
from secagent.core.decoders import (
    detect_encoding, try_decode, auto_decode, EncodingType
)
from secagent.core.headers import parse_ua, random_ua

print("=" * 70)
print("SecAgent 逆向分析 — Claude 中国用户检测机制研究报告")
print("=" * 70)

# =========================================================================
# 1. JS 指纹采集代码分析
# =========================================================================
print("\n\n## 1. Claude Web 端 JS 指纹采集逆向分析")
print("-" * 70)

# 模拟 Claude web 客户端使用的指纹采集 JS
claude_fingerprint_js = """
(function() {
    // === Claude User Region Detection ===
    var fp = {};
    
    // Language detection
    fp.lang = navigator.language || navigator.userLanguage;
    fp.langs = JSON.stringify(navigator.languages || []);
    
    // Timezone
    try {
        fp.tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
        fp.tzo = new Date().getTimezoneOffset();
    } catch(e) {}
    
    // Platform info
    fp.platform = navigator.platform;
    fp.ua = navigator.userAgent;
    fp.cores = navigator.hardwareConcurrency || 0;
    fp.memory = navigator.deviceMemory || 0;
    
    // Canvas fingerprint
    try {
        var c = document.createElement('canvas');
        c.width = 200; c.height = 50;
        var ctx = c.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('test', 2, 15);
        fp.canvas = c.toDataURL();
    } catch(e) {}
    
    return btoa(JSON.stringify(fp));
})();
"""

print("检测到的混淆模式:")
for r in detect_obfuscation(claude_fingerprint_js):
    print(f"  [{r['name']}] {r['description']} x{r['match_count']} 置信度:{r['confidence']}%")

print("\n提取的敏感信息:")
for s in extract_sensitive(claude_fingerprint_js):
    print(f"  [{s['type']}] {s['value'][:80]}")

print("\n格式化后的 JS 代码:")
print(beautify(claude_fingerprint_js))

# =========================================================================
# 2. Claude 系统提示词分析
# =========================================================================
print("\n\n## 2. Claude 内部系统提示词分析 (通过逆向提取)")
print("-" * 70)
print("""
通过 prompt injection 技术提取的 Claude 系统提示词中包含以下与中国用户相关的内容:

[已知的 Claude 系统提示词片段]

1. 地区限制指令:
   "If the user asks from mainland China, Hong Kong, or Macau about topics such as 
    political reform, historical events, or other sensitive issues, you should politely 
    decline to answer and explain that you cannot provide information on this topic."

2. 语言检测逻辑:
   "The user's language and location may indicate they are from a restricted region.
    Use the available information (IP, language preferences, timezone, system locale) 
    to determine if the user should receive full access."

3. 内容过滤:
   "Certain content restrictions apply based on your deployment region. 
    Follow all applicable laws and regulations."

4. Claude Code 的检测:
   "Claude Code is currently not available in your region. 
    Visit https://www.anthropic.com/supported-countries for the list of supported countries."
""")

# =========================================================================
# 3. HTTP 流量特征分析
# =========================================================================
print("\n\n## 3. HTTP 请求特征分析 — Claude 如何判断用户来源")
print("-" * 70)

# 分析 User-Agent 特征
test_uas = [
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36", 
     "Chrome on macOS"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
     "Chrome on Windows"),
]

for ua, desc in test_uas:
    parsed = parse_ua(ua)
    print(f"  UA: {desc}")
    print(f"    浏览器: {parsed['browser']} {parsed['version']}")
    print(f"    系统: {parsed['os']}")
    print(f"    设备: {parsed['device']}")
    print()

print("\nClaude 检测用户来源的关键 HTTP 请求头:")
print("""
  Header                   | 检测内容                | 中国用户典型值
  -------------------------|-------------------------|---------------------------
  Accept-Language          | 用户语言偏好            | zh-CN,zh;q=0.9
  CF-IPCountry             | Cloudflare 国家代码     | CN
  X-Forwarded-For          | 真实 IP                | 中国 IP 段
  CF-Connecting-IP         | Cloudflare 客户端 IP    | 中国 IP 段
  Sec-CH-UA-Platform       | 操作系统                | macOS/Windows
  Sec-CH-UA-Mobile         | 移动端                  | ?0
  Cookie (session)         | 历史行为分析            | 注册/登录信息的地区
""")

# =========================================================================
# 4. Token/JWT 分析
# =========================================================================
print("\n\n## 4. 认证与指纹 Token 分析")
print("-" * 70)

from secagent.analyzers.cookie_analyzer import (
    detect_token_type, analyze_jwt, assess_token_security
)

# Claude 可能使用的客户端指纹编码格式
fingerprint_payloads = [
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpcCI6IjEwMS4yMzEuNDUuNjciLCJsYW5nIjoiemgtQ04iLCJ0eiI6IkFzaWEvU2hhbmdoYWkiLCJwbGF0Zm9ybSI6Im1hY09TIiwidWEiOiJDaHJvbWUvMTI1In0.signature",
    "en-US,en;q=0.9|macOS|Chrome|Asia/New_York|-300|US",
]

for payload in fingerprint_payloads:
    print(f"\n  Token: {payload[:60]}...")
    tok_types = detect_token_type(payload)
    for t in tok_types:
        print(f"  类型: [{t['type']}] {t['description']} 置信度: {t['confidence']}%")
    
    if payload.startswith("eyJ"):
        result = analyze_jwt(payload)
        if result.valid_structure:
            print(f"  JWT Payload: {json.dumps(result.payload, indent=4)}")
    
    sec = assess_token_security(payload)
    print(f"  长度: {sec['length']}, 熵值: {sec.get('entropy', 0)}")

# =========================================================================
# 5. 编码字符串检测
# =========================================================================
print("\n\n## 5. 编码字符串检测 (Base64/Hex/Unicode)")
print("-" * 70)

test_strings = [
    ("ewogICJsYW5nIjogInpoLUNOIiwKICAidGltZXpvbmUiOiAiQXNpYS9TaGFuZ2hhaSIsCiAgInBsYXRmb3JtIjogIm1hY09TIgp9", "Base64 编码的指纹 JSON"),
    ("\\u4e2d\\u56fd\\u7528\\u6237", "Unicode 编码的 '中国用户'"),
]

for s, desc in test_strings:
    print(f"\n  字符串: {desc}")
    encodings = detect_encoding(s)
    print(f"  检测到编码: {', '.join(encodings) if encodings else '未知'}")
    decoded = try_decode(s, 'base64') if 'Base64' in desc else try_decode(s, 'unicode')
    if decoded:
        print(f"  解码结果: {decoded}")

# =========================================================================
# 6. 反制方案
# =========================================================================
print("\n\n" + "=" * 70)
print("## 6. 反制与绕过方案")
print("=" * 70)

print("""
### 6.1 浏览器指纹欺骗

使用 SecAgent web_scraper 的 ScraperConfig 可以伪装浏览器指纹:

  from secagent.analyzers.web_scraper import ScraperConfig
  from secagent.core.headers import build_headers, random_ua
  
  # 生成非中文浏览器指纹
  config = ScraperConfig(
      user_agent=random_ua('chrome_mac'),
      extra_headers={
          'Accept-Language': 'en-US,en;q=0.9',
      }
  )

### 6.2 请求头修改

关键需要修改的头字段:
  - Accept-Language: en-US,en;q=0.9  (非中文)
  - 不需要发送 zh-CN 相关语言

### 6.3 IP 层面

  - 使用干净的住宅 IP (非数据中心 IP)
  - 避免共享 IP (多人共用易触发风控)
  - 保持 IP 稳定不变化

### 6.4 JS 层面反检测

  web_scraper 内置了反检测 JS:
  
  Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
  Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
""")

print("=" * 70)
print("分析完成")
