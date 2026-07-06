"""Tests for the 3 new MCP reverse-engineering tools in tools_registry."""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from secagent.server.tools_registry import all_tools


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture
def tool_map():
    """Map tool name → ToolDefinition for quick lookup."""
    return {t.name: t for t in all_tools()}


@pytest.fixture
def gate():
    return MagicMock()


def _call(tool_map, name, gate, args):
    return tool_map[name].handler(gate, args)


# ===========================================================================
# decode_value
# ===========================================================================

class TestDecodeValue:

    def test_registered(self, tool_map):
        assert "decode_value" in tool_map

    def test_auto_decode_base64(self, tool_map, gate):
        import base64
        encoded = base64.b64encode(b"hello world").decode()
        result = _call(tool_map, "decode_value", gate, {"operation": "auto_decode", "data": encoded})
        assert result["type"] == "decode_result"
        assert result["final"] == "hello world"

    def test_detect_encoding(self, tool_map, gate):
        result = _call(tool_map, "decode_value", gate, {"operation": "detect", "data": "SGVsbG8="})
        assert result["type"] == "detect_result"
        assert "base64" in result["encodings"]

    def test_hash(self, tool_map, gate):
        result = _call(tool_map, "decode_value", gate, {"operation": "hash", "data": "test", "algorithm": "md5"})
        assert result["type"] == "hash_result"
        assert result["hash"] == "098f6bcd4621d373cade4e832627b4f6"

    def test_timestamp(self, tool_map, gate):
        result = _call(tool_map, "decode_value", gate, {"operation": "timestamp", "data": 1712345678})
        assert result["type"] == "timestamp_result"
        assert "2024" in result["ymd"]

    def test_jwt_decode(self, tool_map, gate):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = _call(tool_map, "decode_value", gate, {"operation": "jwt_decode", "data": jwt})
        assert result["type"] == "jwt_result"
        assert result["valid"] is True

    def test_unknown_operation(self, tool_map, gate):
        result = _call(tool_map, "decode_value", gate, {"operation": "bogus", "data": "x"})
        assert result["type"] == "error"


# ===========================================================================
# analyze_web
# ===========================================================================

class TestAnalyzeWeb:

    def test_registered(self, tool_map):
        assert "analyze_web" in tool_map

    def test_js_analyze(self, tool_map, gate):
        js = 'var k = "AIzaSyDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXx"; eval(atob("VGhpcyBpcyBhIHRlc3QgcGF5bG9hZA=="))'
        result = _call(tool_map, "analyze_web", gate, {"operation": "js_analyze", "data": js})
        assert result["type"] == "js_analysis"
        assert len(result["sensitive"]) >= 1
        assert len(result["obfuscation"]) >= 1

    def test_header_fingerprint(self, tool_map, gate):
        import json
        headers = json.dumps({"Server": "cloudflare", "CF-Ray": "abc"})
        result = _call(tool_map, "analyze_web", gate, {"operation": "header_fingerprint", "headers_json": headers})
        assert result["type"] == "header_fingerprint"
        assert any(w["name"] == "Cloudflare" for w in result["wafs"])

    def test_url_params(self, tool_map, gate):
        result = _call(tool_map, "analyze_web", gate, {"operation": "url_params", "data": "https://x.com/api?sign=abc&ts=123"})
        assert result["type"] == "url_params"
        assert len(result["signals"]) >= 1

    def test_unknown_operation(self, tool_map, gate):
        result = _call(tool_map, "analyze_web", gate, {"operation": "bogus"})
        assert result["type"] == "error"


# ===========================================================================
# inspect_token
# ===========================================================================

class TestInspectToken:

    def test_registered(self, tool_map):
        assert "inspect_token" in tool_map

    def test_detect_jwt(self, tool_map, gate):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = _call(tool_map, "inspect_token", gate, {"operation": "detect", "token": jwt})
        assert result["type"] == "token_detect"
        assert any(t["type"] == "jwt" for t in result["token_types"])

    def test_jwt_analysis(self, tool_map, gate):
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = _call(tool_map, "inspect_token", gate, {"operation": "jwt", "token": jwt})
        assert result["type"] == "jwt_analysis"
        assert result["valid"] is True
        assert result["algorithm"] == "HS256"

    def test_cookie_analysis(self, tool_map, gate):
        result = _call(tool_map, "inspect_token", gate, {"operation": "cookie", "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", "cookie_name": "auth_token"})
        assert result["type"] == "cookie_analysis"
        assert result["is_auth"] is True

    def test_security_assessment(self, tool_map, gate):
        result = _call(tool_map, "inspect_token", gate, {"operation": "security", "token": "123"})
        assert result["type"] in ("security_assessment", "generic")
        assert len(result["issues"]) >= 1

    def test_unknown_operation(self, tool_map, gate):
        result = _call(tool_map, "inspect_token", gate, {"operation": "bogus", "token": "x"})
        assert result["type"] == "error"
