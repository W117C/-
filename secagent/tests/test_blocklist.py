from __future__ import annotations

import pytest

from secagent.core.blocklist import Blocklist
from secagent.core.errors import ComplianceBlockError


def test_government_tld_blocked():
    bl = Blocklist()
    assert bl.is_blocked("whitehouse.gov")[0] is True
    assert bl.is_blocked("defence.mil")[0] is True


def test_normal_domain_allowed():
    bl = Blocklist()
    blocked, _ = bl.is_blocked("acme.com")
    assert blocked is False


def test_private_ip_blocked():
    bl = Blocklist()
    assert bl.is_blocked("10.0.0.5")[0] is True
    assert bl.is_blocked("192.168.1.1")[0] is True
    assert bl.is_blocked("172.16.0.1")[0] is True


def test_loopback_blocked():
    bl = Blocklist()
    assert bl.is_blocked("127.0.0.1")[0] is True


def test_cloud_metadata_blocked():
    bl = Blocklist()
    assert bl.is_blocked("169.254.169.254")[0] is True


def test_public_ip_allowed():
    bl = Blocklist()
    assert bl.is_blocked("203.0.113.10")[0] is False


def test_check_raises_on_blocked():
    bl = Blocklist()
    with pytest.raises(ComplianceBlockError) as exc_info:
        bl.check("example.gov")
    assert "gov" in str(exc_info.value.reason).lower()


def test_custom_domain_blocklist_loaded_from_json(tmp_path):
    import json
    bl_file = tmp_path / "bl.json"
    bl_file.write_text(json.dumps({"domains": ["evil-corp.com"]}))
    bl = Blocklist(blocklist_path=str(bl_file))
    assert bl.is_blocked("evil-corp.com")[0] is True
