"""Tests for analyzers: js_reverser, api_signer, cookie_analyzer."""
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
from secagent.analyzers.cookie_analyzer import (
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

_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


# ======================================================================
# js_reverser
# ======================================================================

class TestJsReverser:

    def test_beautify_adds_newlines(self):
        ugly = "function a(){var b=1;return b}"
        assert "\n" in beautify(ugly)

    def test_detect_obfuscation_eval(self):
        obs = detect_obfuscation('eval(atob("TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQ="))')
        names = {o["name"] for o in obs}
        assert "eval" in names
        assert "atob" in names

    def test_detect_obfuscation_hex_escape(self):
        obs = detect_obfuscation(r'"\x48\x65\x6c\x6c\x6f"')
        assert any(o["name"] == "hex_escape" for o in obs)

    def test_detect_obfuscation_unicode_escape(self):
        obs = detect_obfuscation(r'"\u0048\u0065\u006c\x6c\x6f"')
        names = {o["name"] for o in obs}
        assert "unicode_escape" in names

    def test_detect_obfuscation_string_concat(self):
        obs = detect_obfuscation('"a"+"b"+"c"+"d"+"e"')
        assert any(o["name"] == "string_concat" for o in obs)

    def test_detect_obfuscation_self_executing(self):
        obs = detect_obfuscation("(function(){return 1})()")
        assert any(o["name"] == "self_executing" for o in obs)

        obs = detect_obfuscation("}(payload,64,64,'abc|def|ghi'.split('|'))")

    def test_detect_obfuscation_clean_code(self):
        obs = detect_obfuscation("var x = 1; console.log(x);")
        assert len(obs) == 0

    def test_extract_sensitive_google_api_key(self):
        js = 'var k = "AIzaSyDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVv";'
        sens = extract_sensitive(js)
        assert any(s["type"] == "google_api" for s in sens)

    def test_extract_sensitive_aws_key(self):
        js = 'var k = "AKIAIOSFODNN7EXAMPLE";'
        sens = extract_sensitive(js)
        assert any(s["type"] == "aws_key" for s in sens)

    def test_extract_sensitive_github_token(self):
        js = 'var t = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ1234567890";'
        sens = extract_sensitive(js)
        assert any(s["type"] == "github_token" for s in sens)

    def test_extract_sensitive_private_key(self):
        js = '"-----BEGIN RSA PRIVATE KEY-----\\nABCD"'
        sens = extract_sensitive(js)
        assert any(s["type"] == "private_key" for s in sens)

    def test_extract_sensitive_email(self):
        js = '"contact@example.com"'
        sens = extract_sensitive(js)
        assert any(s["type"] == "email" for s in sens)

    def test_extract_sensitive_noise_only(self):
        js = 'var a = 1; var b = 2;'
        sens = extract_sensitive(js)
        assert len(sens) == 0

    def test_try_decrypt_sojson(self):
        decoded = try_decrypt_sojson("\\u0061\\u006c\\u0065\\u0072\\u0074(1)")
        assert decoded is not None
        assert "alert" in decoded

    def test_decode_hex_strings(self):
        js = r"'\x48\x65\x6c\x6c\x6f'"
        r = decode_hex_strings(js)
        # hex strings with \xHH escapes
        assert isinstance(r, dict)


# ======================================================================
# api_signer
# ======================================================================

class TestApiSigner:

    def test_detect_signature_params(self):
        params = {"user": "admin", "sign": "abc", "ts": "123", "token": "xyz"}
        sp = detect_signature_params(params)
        assert "sign" in sp
        assert "ts" in sp
        assert "token" in sp
        assert "user" not in sp

    def test_detect_signature_params_empty(self):
        assert detect_signature_params({"name": "x"}) == []

    def test_classify_params(self):
        params = {"user": "admin", "sign": "abc", "ts": "123", "_": "nocache"}
        cls = classify_params(params)
        assert len(cls["business"]) == 1  # user
        assert len(cls["security"]) >= 2  # sign + ts
        assert len(cls["meta"]) == 1       # _

    def test_build_sign_string_lexical(self):
        params = {"z": "1", "a": "2", "m": "3"}
        s = build_sign_string(params, SignatureConfig(sort_method="lexical"))
        parts = s.split("&")
        assert parts == ["a=2", "m=3", "z=1"]

    def test_build_sign_string_excludes_sig(self):
        params = {"user": "admin", "sign": "abc", "sig": "def"}
        s = build_sign_string(params, SignatureConfig())
        assert "sign=" not in s
        assert "sig=" not in s

    def test_build_sign_string_with_secret(self):
        params = {"a": "1"}
        s = build_sign_string(params, SignatureConfig(append_secret="secret123"))
        assert s == "a=1secret123"

    def test_compute_sign_md5(self):
        r = compute_sign("a=1&b=2", "md5")
        assert len(r) == 32
        assert r == "ed04c91cf6f6ab5a01a31c0295c5da34"

    def test_compute_sign_sha256(self):
        r = compute_sign("test", "sha256")
        assert len(r) == 64

    def test_compute_sign_hmac(self):
        r = compute_sign("test", "hmac-sha256", secret="key")
        assert len(r) == 64

    def test_compute_sign_hmac_no_secret_raises(self):
        import pytest
        with pytest.raises(ValueError, match="requires a secret"):
            compute_sign("test", "hmac-sha256")

    def test_bruteforce_finds_match(self):
        params = {"a": "1", "b": "2"}
        known = compute_sign("a=1&b=2", "md5")
        results = brute_force_sign_algorithm(
            params, known, candidates=["md5"], secrets=[None]
        )
        assert len(results) >= 1
        assert results[0]["algorithm"] == "md5"

    def test_bruteforce_no_match(self):
        params = {"a": "1", "b": "2"}
        results = brute_force_sign_algorithm(
            params, "deadbeef" * 4, candidates=["md5"], secrets=[None]
        )
        assert len(results) == 0

    def test_request_replayer_chain(self):
        cr = CapturedRequest(
            method="POST", url="https://x.com/login",
            params={"user": "admin", "pass": "123"},
        )
        rr = RequestReplayer(cr)
        rr.modify_param("user", "root").modify_param("pass", "456").remove_param("pass")
        assert rr.get_params() == {"user": "root"}

    def test_request_replayer_summary(self):
        cr = CapturedRequest(method="GET", url="https://x.com/data",
                             params={"sign": "abc", "ts": "123"})
        s = RequestReplayer(cr).summary()
        assert s["method"] == "GET"
        assert s["params_count"] == 2
        assert s["signature_params"]

    def test_analyze_api_auth(self):
        cap = CapturedRequest(
            method="POST", url="https://x.com/api",
            params={"id": "123", "sign": "abc", "ts": "1712345678"},
        )
        r = analyze_api_auth(cap)
        assert r["method"] == "POST"
        assert r["param_count"] == 3
        assert r["suggested_bruteforce"] is False


# ======================================================================
# cookie_analyzer
# ======================================================================

class TestCookieAnalyzer:

    def test_detect_token_type_jwt(self):
        tt = detect_token_type(_JWT)
        types = {t["type"] for t in tt}
        assert "jwt" in types

    def test_detect_token_type_uuid(self):
        tt = detect_token_type("550e8400-e29b-41d4-a716-446655440000")
        types = {t["type"] for t in tt}
        assert "uuid" in types

    def test_detect_token_type_hex(self):
        tt = detect_token_type("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6")
        types = {t["type"] for t in tt}
        assert "hex_token" in types

    def test_detect_token_type_numeric(self):
        tt = detect_token_type("12345678901")
        types = {t["type"] for t in tt}
        assert "numeric_id" in types

    def test_detect_token_type_short(self):
        assert detect_token_type("abc") == []

    def test_analyze_jwt_valid(self):
        r = analyze_jwt(_JWT)
        assert r.valid_structure
        assert r.algorithm == "HS256"
        assert r.subject == "1234567890"
        assert r.issued_at

    def test_analyze_jwt_invalid(self):
        r = analyze_jwt("not.a.jwt")
        assert not r.payload  # 3 parts but not valid base64
        r2 = analyze_jwt("")
        assert not r2.valid_structure

    def test_analyze_jwt_claims(self):
        payload = {"sub": "123", "name": "John", "iat": 1516239022, "role": "admin"}
        r = analyze_jwt_claims(payload)
        assert "sub" in r["standard_claims"]
        assert r["user_claims"].get("name") == "John"
        assert "admin" in r["permissions"]

    def test_analyze_cookie_auth(self):
        ck = analyze_cookie("auth_token", _JWT)
        assert ck.is_auth
        assert len(ck.token_type) > 0

    def test_analyze_cookie_session(self):
        ck = analyze_cookie("session_id", "abc123def456")
        assert ck.is_session
        # Don't try to decode short values
        assert len(ck.token_type) == 0

    def test_analyze_cookie_encrypted(self):
        """Long base64-like values marked as potentially encrypted."""
        import base64
        long_val = base64.b64encode(b"x" * 30).decode()
        ck = analyze_cookie("data", long_val)
        assert ck.is_encrypted

    def test_analyze_cookies_multiple(self):
        cookies = analyze_cookies({"token": _JWT, "session": "abc"})
        # auth cookies should sort first
        assert len(cookies) == 2
        assert cookies[0].is_auth

    def test_assess_jwt_security(self):
        r = assess_token_security(_JWT)
        assert r["type"] == "JWT"
        assert r["algorithm"] == "HS256"
        assert r["entropy"] > 0

    def test_assess_short_token(self):
        r = assess_token_security("12345")
        assert len(r["issues"]) >= 1
        assert r["type"] == "generic"

    def test_assess_numeric_token(self):
        r = assess_token_security("12345678901")
        assert any("Numeric" in i for i in r["issues"])
