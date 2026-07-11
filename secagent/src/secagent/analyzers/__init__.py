"""SecAgent Web 逆向分析器集合 — JS 反混淆、API 签名、Cookie/JWT、流量分析、爬虫。

统一导出所有 analyzers 和核心工具函数。
"""
from __future__ import annotations

from secagent.analyzers.api_signer import (
    CapturedRequest,
    RequestReplayer,
    SignatureConfig,
    analyze_api_auth,
    brute_force_sign_algorithm,
    build_sign_string,
    classify_params,
    compute_sign,
    detect_signature_params,
)
from secagent.analyzers.binary_analyzer import (
    analyze_binary,
    detect_packing,
    disassemble_function,
    extract_strings,
)
from secagent.analyzers.cli_reverser import (
    BinaryAnalysis,
    CLIReverseReport,
    EnvironmentFingerprint,
    InstallScriptAnalysis,
    TokenAnalysis,
    analyze_binary_packaging,
    analyze_install_script,
    analyze_token,
    detect_fingerprint_fields,
)
from secagent.analyzers.cookie_analyzer import (
    CookieInfo,
    JWTResult,
    analyze_cookie,
    analyze_cookies,
    analyze_jwt,
    analyze_jwt_claims,
    assess_token_security,
    detect_token_type,
)
from secagent.analyzers.js_reverser import (
    beautify,
    decode_hex_strings,
    detect_obfuscation,
    extract_sensitive,
    try_decrypt_sojson,
)
from secagent.analyzers.traffic_analyzer import (
    HTTPEntry,
    RequestChain,
    analyze_traffic_flow,
    parse_har,
)
from secagent.analyzers.web_scraper import (
    RequestInterceptor,
    ScraperConfig,
    SessionManager,
    generate_mouse_trace,
    generate_typing_delay,
)
from secagent.core.decoders import (
    EncodingType,
    analyze_timestamp,
    auto_decode,
    decode_jwt,
    decode_set_cookie,
    detect_encoding,
    encode,
    generate_timestamp,
    hash_text,
    try_decode,
)
from secagent.core.headers import (
    RequestParam,
    analyze_url_params,
    build_headers,
    fingerprint_headers,
    parse_ua,
    random_ua,
)

__all__ = [
    "EncodingType", "analyze_timestamp", "auto_decode", "decode_jwt",
    "decode_set_cookie", "detect_encoding", "encode", "generate_timestamp",
    "hash_text", "try_decode",
    "RequestParam", "analyze_url_params", "build_headers",
    "fingerprint_headers", "parse_ua", "random_ua",
    "beautify", "decode_hex_strings", "detect_obfuscation",
    "extract_sensitive", "try_decrypt_sojson",
    "CapturedRequest", "RequestReplayer", "SignatureConfig",
    "analyze_api_auth", "brute_force_sign_algorithm", "build_sign_string",
    "classify_params", "compute_sign", "detect_signature_params",
    "CookieInfo", "JWTResult", "analyze_cookie", "analyze_cookies",
    "analyze_jwt", "analyze_jwt_claims", "assess_token_security",
    "detect_token_type",
    "HTTPEntry", "RequestChain", "analyze_traffic_flow", "parse_har",
    "RequestInterceptor", "ScraperConfig", "SessionManager",
    "generate_mouse_trace", "generate_typing_delay",
    "analyze_binary", "disassemble_function", "extract_strings", "detect_packing",
    "CLIReverseReport", "InstallScriptAnalysis", "EnvironmentFingerprint",
    "TokenAnalysis", "BinaryAnalysis",
    "analyze_install_script", "detect_fingerprint_fields",
    "analyze_token", "analyze_binary_packaging",
]
