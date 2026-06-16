"""Unified error model for SecAgent (spec §3.1).

Every error carries an ErrorCode, a human-readable message, and a retryable flag.
`to_error_dict` renders the error into the JSON shape tools return to the agent.
"""
from __future__ import annotations

from enum import Enum


class ErrorCode(str, Enum):
    NOT_AUTHORIZED = "NOT_AUTHORIZED"
    COMPLIANCE_BLOCK = "COMPLIANCE_BLOCK"
    RATE_LIMITED = "RATE_LIMITED"
    TOOL_TIMEOUT = "TOOL_TIMEOUT"
    TOOL_FAILED = "TOOL_FAILED"
    INVALID_INPUT = "INVALID_INPUT"


class SecAgentError(Exception):
    """Base class for all SecAgent errors."""

    code: ErrorCode = ErrorCode.TOOL_FAILED
    retryable: bool = False

    @property
    def message(self) -> str:
        return str(self.args[0]) if self.args else self.__class__.__name__


class NotAuthorizedError(SecAgentError):
    code = ErrorCode.NOT_AUTHORIZED
    retryable = False

    def __init__(self, target: str, scope_domain: str | None = None):
        self.target = target
        self.scope_domain = scope_domain
        scope_txt = f" (scope: {scope_domain})" if scope_domain else ""
        super().__init__(f"Target '{target}' is not within authorized scope{scope_txt}")


class ComplianceBlockError(SecAgentError):
    code = ErrorCode.COMPLIANCE_BLOCK
    retryable = False

    def __init__(self, target: str, reason: str):
        self.target = target
        self.reason = reason
        super().__init__(f"Target '{target}' blocked by compliance policy: {reason}")


class RateLimitedError(SecAgentError):
    code = ErrorCode.RATE_LIMITED
    retryable = True

    def __init__(self, detail: str = "quota exhausted"):
        super().__init__(detail)


class ToolTimeoutError(SecAgentError):
    code = ErrorCode.TOOL_TIMEOUT
    retryable = True

    def __init__(self, tool: str, target: str):
        self.tool = tool
        self.target = target
        super().__init__(f"Tool '{tool}' timed out on target '{target}'")


class ToolFailedError(SecAgentError):
    code = ErrorCode.TOOL_FAILED
    retryable = True

    def __init__(self, tool: str, detail: str):
        self.tool = tool
        super().__init__(f"Tool '{tool}' failed: {detail}")


class InvalidInputError(SecAgentError):
    code = ErrorCode.INVALID_INPUT
    retryable = False

    def __init__(self, field: str, reason: str):
        self.field = field
        super().__init__(f"Invalid input for '{field}': {reason}")


def to_error_dict(err: SecAgentError) -> dict:
    return {
        "error": {
            "code": err.code.value,
            "message": err.message,
            "retryable": err.retryable,
        }
    }
