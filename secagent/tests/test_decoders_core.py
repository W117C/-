"""Tests for core/decoders.py — encoding detection, conversion, JWT, cookies."""
from __future__ import annotations

import json

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


# ==========================================================================
# detect_encoding
# ==========================================================================

def test_detect_base64():
    assert "base64" in detect_encoding("SGVsbG8=")


def test_detect_hex():
    assert "hex" in detect_encoding("48656c6c6f")


def test_detect_url():
    enc = detect_encoding("Hello%20World%21")
    assert "url" in enc


def test_detect_unicode_escape():
    enc = detect_encoding("\\u0048\\u0065\\u006c\\u006c\\u006f")
    assert "unicode" in enc


def test_detect_empty_string():
    assert detect_encoding("") == []


def test_detect_none_input():
    assert detect_encoding(None) == []   # type: ignore[arg-type]


# ==========================================================================
# try_decode
# ==========================================================================

def test_decode_base64():
    assert try_decode("SGVsbG8gV29ybGQ=", "base64") == "Hello World"


def test_decode_base64_padding_tolerant():
    """JWT-like unpadded base64 should still decode."""
    import base64
    raw = base64.b64encode(b"Hello").decode().rstrip("=")
    assert try_decode(raw, "base64") == "Hello"


def test_decode_base64_urlsafe():
    assert try_decode("SGVsbG8gV29ybGQ=", "base64_urlsafe") == "Hello World"


def test_decode_hex():
    assert try_decode("48656c6c6f", "hex") == "Hello"


def test_decode_url():
    assert try_decode("Hello%20World", "url") == "Hello World"


def test_decode_double_url():
    assert try_decode("Hello%2520World", "double_url") == "Hello World"


def test_decode_rot13():
    assert try_decode("Uryyb Jbeyq", "rot13") == "Hello World"


def test_decode_unicode_escape():
    r = try_decode("\\u0048\\u0065\\u006c\\u006c\\u006f", "unicode")
    assert r and "Hello" in r


def test_decode_html_entity():
    assert try_decode("&lt;script&gt;", "html_entity") == "<script>"


def test_decode_base32():
    assert try_decode("NBSWY3DP", "base32") == "hello"


def test_decode_garbage_returns_string():
    assert isinstance(try_decode("!!!not-encoded!!!", "base64"), str)


# ==========================================================================
# auto_decode
# ==========================================================================

def test_auto_decode_single_layer_base64():
    result = auto_decode("SGVsbG8=", max_depth=3)
    assert len(result) >= 1
    assert result[-1]["result"] == "Hello"


def test_auto_decode_nested_base64_json():
    data = json.dumps({"name": "test", "value": 42})
    encoded = encode(data, "base64")
    result = auto_decode(encoded, max_depth=3)
    assert len(result) >= 1
    assert result[-1]["is_json"] is True
    assert result[-1]["parsed"]["name"] == "test"


def test_auto_decode_double_base64():
    inner = encode("hello", "base64")
    outer = encode(inner, "base64")
    result = auto_decode(outer, max_depth=3)
    assert len(result) >= 1  # at least one decode layer


def test_auto_decode_not_encodable():
    assert auto_decode("plain text no encoding") == []


# ==========================================================================
# encode
# ==========================================================================

def test_encode_base64():
    assert encode("Hello", "base64") == "SGVsbG8="


def test_encode_hex():
    assert encode("Hello", "hex") == "48656c6c6f"


def test_encode_url():
    assert encode("a b", "url") == "a%20b"


def test_encode_rot13():
    assert encode("Hello", "rot13") == "Uryyb"


def test_encode_unknown_raises():
    import pytest
    with pytest.raises(ValueError, match="unsupported encoding"):
        encode("x", "unknown_encoding")


# ==========================================================================
# hash_text
# ==========================================================================

def test_hash_md5():
    assert hash_text("test", "md5") == "098f6bcd4621d373cade4e832627b4f6"


def test_hash_sha1():
    assert len(hash_text("test", "sha1")) == 40


def test_hash_sha256():
    assert len(hash_text("test", "sha256")) == 64


def test_hash_sha512():
    assert len(hash_text("test", "sha512")) == 128


def test_hash_unknown_raises():
    import pytest
    with pytest.raises(ValueError, match="unknown hash algorithm"):
        hash_text("x", "unknown")


# ==========================================================================
# analyze_timestamp
# ==========================================================================

def test_timestamp_seconds():
    r = analyze_timestamp(1712345678)
    assert r["precision"] == "seconds"
    assert "2024-04-05" in r["ymd"]
    assert "utc_iso" in r


def test_timestamp_milliseconds():
    r = analyze_timestamp(1712345678000)
    assert r["precision"] == "milliseconds"


def test_timestamp_microseconds():
    r = analyze_timestamp(1712345678000000)
    assert r["precision"] == "microseconds"


def test_timestamp_string_input():
    r = analyze_timestamp("1712345678")
    assert r["precision"] == "seconds"


def test_timestamp_invalid_input():
    r = analyze_timestamp("not-a-timestamp")
    assert "error" in r


# ==========================================================================
# generate_timestamp
# ==========================================================================

def test_gen_unix():
    v = generate_timestamp("unix")
    assert isinstance(v, int) and v > 1_700_000_000


def test_gen_js():
    v = generate_timestamp("js")
    assert isinstance(v, int) and v > 1_700_000_000_000


def test_gen_iso():
    v = generate_timestamp("iso")
    assert isinstance(v, str) and "T" in v


def test_gen_unknown_style_raises():
    import pytest
    with pytest.raises(ValueError, match="unknown timestamp style"):
        generate_timestamp("bad")


# ==========================================================================
# decode_jwt
# ==========================================================================

_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
    "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_jwt_decode_header():
    r = decode_jwt(_JWT)
    assert r is not None
    assert isinstance(r["header"], dict)
    assert r["header"]["alg"] == "HS256"


def test_jwt_decode_payload():
    r = decode_jwt(_JWT)
    assert isinstance(r["payload"], dict)
    assert r["payload"]["sub"] == "1234567890"
    assert r["payload"]["name"] == "John Doe"


def test_jwt_signature_present():
    r = decode_jwt(_JWT)
    assert isinstance(r["signature"], str) and len(r["signature"]) > 10


def test_jwt_invalid_format():
    assert decode_jwt("not-a-jwt") is None
    assert decode_jwt("a.b") is None
    assert decode_jwt("") is None
    assert decode_jwt("...") is None


# ==========================================================================
# decode_set_cookie
# ==========================================================================

def test_set_cookie_basic():
    r = decode_set_cookie("sid=abc123")
    assert r["name"] == "sid"
    assert r["value"] == "abc123"


def test_set_cookie_with_attributes():
    r = decode_set_cookie("token=xyz; Path=/; Domain=.example.com; Secure; HttpOnly")
    assert r["name"] == "token"
    assert r["attributes"]["path"] == "/"
    assert r["attributes"]["secure"] is True
    assert r["attributes"]["httponly"] is True


def test_set_cookie_samesite():
    r = decode_set_cookie("sess=1; SameSite=Lax")
    assert r["attributes"]["samesite"] == "Lax"


def test_set_cookie_empty_value():
    r = decode_set_cookie("empty=")
    assert r["name"] == "empty"
    assert r["value"] == ""
