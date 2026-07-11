"""Bilibili 全链路逆向分析 — SecAgent 工具链实战"""
import sys, os, json, re, hashlib, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from secagent.analyzers.js_reverser import beautify, detect_obfuscation, extract_sensitive, extract_encoded_strings
from secagent.analyzers.cookie_analyzer import analyze_jwt, detect_token_type, analyze_cookie, assess_token_security
from secagent.analyzers.api_signer import detect_signature_params, classify_params, build_sign_string, SignatureConfig, compute_sign
from secagent.core.decoders import detect_encoding, try_decode, auto_decode
from secagent.core.headers import parse_ua, fingerprint_headers, random_ua

print("=" * 70)
print("🔥 SecAgent — Bilibili 全链路逆向分析")
print("=" * 70)

# 1. wbi 签名算法
print("\n## 1. wbi 签名算法逆向")
print("-" * 70)
img_key = "7cd084941338484aae1ad9425b84077c"
sub_key = "4932caff0ff746eab6f01bf08b70ac45"
mix_key = sub_key[:4] + img_key[:4]
print(f"img_key={img_key[:20]}... sub_key={sub_key[:20]}...")
print(f"mix_key = sub_key[:4] + img_key[:4] = {mix_key}")

params = {"aid": "1205961180", "cid": "26544153927", "type": "json"}
wts = int(time.time())
sorted_str = "&".join(f"{k}={v}" for k, v in sorted(params.items()))
w_rid = hashlib.md5((sorted_str + mix_key).encode()).hexdigest()
print(f"签名: w_rid={w_rid} wts={wts}")
print(f"公式: MD5('{sorted_str}' + '{mix_key}')")

# 2. JS 混淆检测
print("\n## 2. JS 混淆检测")
print("-" * 70)
detect_obfuscation('var t9=Object.defineProperty;var n9=(e,t,n)=>t in e?t9(e,t,{}):e[t]=n;')

# 3. Cookie 分析
print("\n## 3. Cookie 分析")
print("-" * 70)
for name in ["SESSDATA", "buvid3", "bili_jct", "DedeUserID"]:
    analyze_cookie(name, "test_value")

# 4. 编码检测
print("\n## 4. 编码检测")
print("-" * 70)
for val, desc in [
    ("aHR0cHM6Ly9hcGkuYmlsaWJpbGkuY29t", "B站 API Base64"),
    ("\\u89c6\\u9891\\u64ad\\u653e", "Unicode 中文"),
]:
    dec = detect_encoding(val)
    print(f"  {desc}: {dec}")

print("\n" + "=" * 70)
print("✅ Bilibili 逆向分析完成")
