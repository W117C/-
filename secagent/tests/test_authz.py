from __future__ import annotations

import pytest

from secagent.core.authz import AuthorizationScope, ScopeType, check_target_in_scope
from secagent.core.errors import NotAuthorizedError


def test_domain_scope_matches_subdomain():
    scope = AuthorizationScope(ScopeType.DOMAIN, "acme.com")
    assert check_target_in_scope("sub.acme.com", scope) is True
    assert check_target_in_scope("acme.com", scope) is True
    assert check_target_in_scope("deep.nested.acme.com", scope) is True


def test_domain_scope_rejects_other_domain():
    scope = AuthorizationScope(ScopeType.DOMAIN, "acme.com")
    assert check_target_in_scope("acme.com.evil.com", scope) is False
    assert check_target_in_scope("notacme.com", scope) is False


def test_ip_scope_exact_match():
    scope = AuthorizationScope(ScopeType.IP, "203.0.113.10")
    assert check_target_in_scope("203.0.113.10", scope) is True
    assert check_target_in_scope("203.0.113.11", scope) is False


def test_cidr_scope_match():
    scope = AuthorizationScope(ScopeType.CIDR, "203.0.113.0/24")
    assert check_target_in_scope("203.0.113.50", scope) is True
    assert check_target_in_scope("203.0.114.50", scope) is False


def test_repo_scope_match():
    scope = AuthorizationScope(ScopeType.REPO, "github.com/acme")
    assert check_target_in_scope("github.com/acme/web", scope) is True
    assert check_target_in_scope("github.com/acme", scope) is True
    assert check_target_in_scope("github.com/other/web", scope) is False


def test_email_scope_exact_match():
    scope = AuthorizationScope(ScopeType.EMAIL, "person@acme.com")
    assert check_target_in_scope("person@acme.com", scope) is True
    assert check_target_in_scope("other@acme.com", scope) is False


def test_authorization_record_verify_raises_when_out_of_scope():
    scope = AuthorizationScope(ScopeType.DOMAIN, "acme.com")
    with pytest.raises(NotAuthorizedError):
        AuthorizationScope.verify_or_raise("evil.com", scope)
