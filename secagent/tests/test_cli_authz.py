from __future__ import annotations


from click.testing import CliRunner

from secagent.cli import main


def _run(args, tmp_db, monkeypatch):
    monkeypatch.setenv("SECAGENT_DB_PATH", tmp_db)
    runner = CliRunner()
    return runner.invoke(main, args)


def test_authz_add_emits_token(tmp_path, monkeypatch):
    db = str(tmp_path / "cli.db")
    result = _run(["authz", "add", "--domain", "acme.com"], db, monkeypatch)
    assert result.exit_code == 0, result.output
    assert "auth_" in result.output


def test_authz_list_shows_record(tmp_path, monkeypatch):
    db = str(tmp_path / "cli.db")
    _run(["authz", "add", "--domain", "acme.com"], db, monkeypatch)
    result = _run(["authz", "list"], db, monkeypatch)
    assert result.exit_code == 0
    assert "acme.com" in result.output
    assert "domain" in result.output


def test_authz_verify_marks_verified(tmp_path, monkeypatch):
    db = str(tmp_path / "cli.db")
    add_result = _run(["authz", "add", "--domain", "acme.com"], db, monkeypatch)
    # extract token from output (printed as "token: auth_xxx")
    token = [line.split(":", 1)[1].strip() for line in add_result.output.splitlines() if line.startswith("token:")][0]
    result = _run(["authz", "verify", token, "--method", "dns_txt"], db, monkeypatch)
    assert result.exit_code == 0
    list_result = _run(["authz", "list"], db, monkeypatch)
    assert "verified" in list_result.output.lower()
