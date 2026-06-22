"""Tool function tests for passive_recon."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from secagent.core.errors import InvalidInputError, NotAuthorizedError
from secagent.tools.passive_recon import passive_recon
from helper import setup_gate_and_token


def test_passive_recon_crtsh_only(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)

    with patch("secagent.tools.passive_recon._crt_sh_query") as mock_crt:
        mock_crt.return_value = [
            {"name_value": "sub.acme.com"},
            {"name_value": "blog.acme.com"},
            {"name_value": "*.mail.acme.com"},
        ]
        result = passive_recon(
            gate=gate,
            params={"target": "acme.com", "sources": ["crtsh"]},
            authz_token=token,
        )

    assert result["tool"] == "passive_recon"
    assert len(result["findings"]) >= 2
    targets = {f["target"] for f in result["findings"]}
    assert "sub.acme.com" in targets
    assert "blog.acme.com" in targets
    # Wildcard stripped: mail.acme.com should be included
    assert "mail.acme.com" in targets


def test_passive_recon_empty_sources(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    result = passive_recon(
        gate=gate,
        params={"target": "acme.com", "sources": []},
        authz_token=token,
    )
    assert result["tool"] == "passive_recon"
    assert len(result["findings"]) == 0


def test_passive_recon_default_sources(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.passive_recon._crt_sh_query", return_value=[]):
        with patch("secagent.tools.passive_recon._securitytrails_query", return_value=[]):
            with patch("secagent.tools.passive_recon._shodan_query", return_value=[]):
                result = passive_recon(
                    gate=gate,
                    params={"target": "acme.com"},
                    authz_token=token,
                )
    assert result["tool"] == "passive_recon"


def test_passive_recon_http_failure(tmp_db):
    """When all sources fail, findings should be empty (not crash)."""
    gate, token = setup_gate_and_token(tmp_db)
    with patch("secagent.tools.passive_recon._crt_sh_query", return_value=[]):
        with patch("secagent.tools.passive_recon._securitytrails_query", return_value=[]):
            with patch("secagent.tools.passive_recon._shodan_query", return_value=[]):
                result = passive_recon(
                    gate=gate,
                    params={"target": "acme.com", "sources": ["crtsh", "securitytrails"]},
                    authz_token=token,
                )
    assert result["tool"] == "passive_recon"
    assert len(result["findings"]) == 0


def test_passive_recon_empty_target(tmp_db):
    gate, token = setup_gate_and_token(tmp_db)
    with pytest.raises(InvalidInputError):
        passive_recon(
            gate=gate,
            params={"target": ""},
            authz_token=token,
        )


def test_passive_recon_unauthorized(tmp_db):
    gate, token = setup_gate_and_token(tmp_db, scope_value="other.com")
    with pytest.raises(NotAuthorizedError):
        passive_recon(
            gate=gate,
            params={"target": "acme.com"},
            authz_token=token,
        )
