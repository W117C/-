from __future__ import annotations

import pytest

from secagent.core.errors import (
    ErrorCode,
    NotAuthorizedError,
    ComplianceBlockError,
    RateLimitedError,
    ToolTimeoutError,
    ToolFailedError,
    InvalidInputError,
    to_error_dict,
)


def test_error_code_values():
    assert ErrorCode.NOT_AUTHORIZED.value == "NOT_AUTHORIZED"
    assert ErrorCode.COMPLIANCE_BLOCK.value == "COMPLIANCE_BLOCK"
    assert ErrorCode.RATE_LIMITED.value == "RATE_LIMITED"
    assert ErrorCode.TOOL_TIMEOUT.value == "TOOL_TIMEOUT"
    assert ErrorCode.TOOL_FAILED.value == "TOOL_FAILED"
    assert ErrorCode.INVALID_INPUT.value == "INVALID_INPUT"


def test_not_authorized_is_not_retryable():
    err = NotAuthorizedError(target="evil.com", scope_domain="acme.com")
    d = to_error_dict(err)
    assert d["error"]["code"] == "NOT_AUTHORIZED"
    assert d["error"]["retryable"] is False
    assert "evil.com" in d["error"]["message"]


def test_compliance_block_is_not_retryable():
    err = ComplianceBlockError(target="whitehouse.gov", reason="government TLD")
    d = to_error_dict(err)
    assert d["error"]["code"] == "COMPLIANCE_BLOCK"
    assert d["error"]["retryable"] is False


def test_tool_timeout_is_retryable():
    err = ToolTimeoutError(tool="nuclei", target="acme.com")
    d = to_error_dict(err)
    assert d["error"]["code"] == "TOOL_TIMEOUT"
    assert d["error"]["retryable"] is True


def test_to_error_dict_wraps_arbitrary_secagent_error():
    err = InvalidInputError(field="targets", reason="empty list")
    d = to_error_dict(err)
    assert d["error"]["code"] == "INVALID_INPUT"
    assert d["error"]["retryable"] is False
