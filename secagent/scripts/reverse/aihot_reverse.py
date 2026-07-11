"""AI HOT 网站逆向分析"""
import sys, json, time
sys.path.insert(0, 'src')

from secagent.analyzers.js_reverser import detect_obfuscation, extract_sensitive, beautify
from secagent.analyzers.cookie_analyzer import detect_token_type, assess_token_security
from secagent.core.decoders import detect_encoding, try_decode
from secagent.core.headers import parse_ua

print("=" * 70)
print("🔍 SecAgent 逆向分析报告 — AI HOT (aihot.virxact.com)")
print("=" * 70)

print("""
## 1. 基础信息
  URL:       https://aihot.virxact.com
  Title:     AI HOT — AI 行业动态聚合 (AI 热点)
  Language:  zh-CN (中文)
  Tech:      Next.js 14+ (React SSR) + nginx/1.24.0
  Server:    nginx/1.24.0 (Ubuntu)
  Creator:   卡兹克 (数字生命卡兹克) @Khazix0918
  Company:   虚实传媒 (Virxact)
  License:   Reference Use

## 2. 信源
  - X/Twitter (主要)
  - Hacker News (经 buzzing.cc 中文翻译)
  - RSS Feeds (MarkTechPost, IEEE Spectrum 等)
  - 微信公众号 (仅内部工作台可见)

## 3. 公开 API 端点
  GET /api/public/items        — 条目列表 (mode=selected|all, cursor 翻页)
  GET /api/public/daily        — 日报
  GET /api/public/fingerprint  — 指纹探针 (推荐先轮询此端点)
  GET /api/public/feed         — RSS 格式
  GET /api/img-proxy           — 图片代理 (签名+过期保护)
  GET /openapi.yaml            — API 规范(OpenAPI 3.1)

## 4. API 特性
  限流: 60 req/min/IP, nginx burst
  UA 策略: 不允许纯浏览器 UA, 必须设置自定义标识
  缓存: nginx proxy_cache 60s + ETag/If-None-Match
  翻页: cursor-based (Base64 编码的 nextCursor)
  排序: publishedAt 倒序
  限流响应: HTTP 429 -> 退避 30-60s

## 5. 数据模型
  Item: {
    id, title, title_en, url, permalink, source,
    publishedAt, summary, category, score (0-100),
    selected (bool), tags[], attribution, content?
  }

## 6. 图片代理签名
  URL: /api/img-proxy?u=<encoded_url>&exp=<timestamp>&sig=<SHA256>
  sig = HMAC-SHA256(url + exp, secret)  或 SHA256(url||exp||salt)
  exp = 过期 Unix 时间戳 (图片限时访问)
  防盗链 + 限时 + 域名限制

## 7. 搜索参数
  ?q=<query>&category=<category>&page=<page>&tag=<tag>
  分类: tip(技巧), news(新闻), paper(论文), product(产品), event(事件)

## 8. RSS Feeds
  /feed.xml           — 精选
  /feed/all.xml       — 全部
  /feed/daily.xml     — 日报
  /feed/category/paper.xml — 按分类

## 9. 保护措施
  1. Rate limit: 60 req/min/IP
  2. User-Agent 检测 (防批量爬取)
  3. Image proxy 签名+过期 (防盗链)
  4. nginx 层防护
""")

# 签名分析
sig = "9bb93d0880082317efcdb196e58e6b8c7194d6e3a95329275cd87b1f011f7e70"
print("sig 分析:")
for t in detect_token_type(sig):
    print(f"  类型: [{t['type']}] {t['description']} 置信度:{t['confidence']}%")
print(f"  长度: {len(sig)} → SHA-256 (64 hex chars)")

ts = 1783555200
print(f"  exp = {ts} → {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(ts))}")

print("\n" + "=" * 70)
print("✅ 逆向分析完成")
