"""Defense line 1 — authorization scope + check (spec §4.1).

An AuthorizationScope declares what a customer has authorized scanning of.
`check_target_in_scope` is the single choke point every tool calls before running.
Token issuance/verification-of-ownership happens in the registry (Task 9) + CLI (Task 10).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

from secagent.core.errors import NotAuthorizedError


class ScopeType(str, Enum):
    DOMAIN = "domain"
    IP = "ip"
    CIDR = "cidr"
    REPO = "repo"
    EMAIL = "email"


@dataclass(frozen=True)
class AuthorizationScope:
    type: ScopeType
    value: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "value", self.value.strip().lower())


def check_target_in_scope(target: str, scope: AuthorizationScope) -> bool:
    t = target.strip().lower()
    if scope.type is ScopeType.DOMAIN:
        domain = scope.value
        return t == domain or t.endswith("." + domain)
    if scope.type is ScopeType.IP:
        return t == scope.value
    if scope.type is ScopeType.CIDR:
        try:
            return ipaddress.ip_address(t) in ipaddress.ip_network(scope.value)
        except ValueError:
            return False
    if scope.type is ScopeType.REPO:
        return t == scope.value or t.startswith(scope.value + "/")
    if scope.type is ScopeType.EMAIL:
        return t == scope.value
    return False


def _verify_or_raise(target: str, scope: AuthorizationScope) -> None:
    if not check_target_in_scope(target, scope):
        raise NotAuthorizedError(target=target, scope_domain=scope.value)


# Static helper bound to the dataclass for ergonomic tool-side calls.
AuthorizationScope.verify_or_raise = staticmethod(_verify_or_raise)  # type: ignore[attr-defined]
