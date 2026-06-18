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


# ---------------------------------------------------------------------------
# SSRF guard: IPv6 private/reserved ranges must be blocked too.
# ---------------------------------------------------------------------------

def test_ipv6_loopback_blocked():
    bl = Blocklist()
    assert bl.is_blocked("::1")[0] is True


def test_ipv6_unique_local_address_blocked():
    bl = Blocklist()
    assert bl.is_blocked("fd00:ec2::254")[0] is True  # IPv6 metadata-style
    assert bl.is_blocked("fc00::1")[0] is True


def test_ipv6_link_local_blocked():
    bl = Blocklist()
    assert bl.is_blocked("fe80::1")[0] is True


def test_ipv4_mapped_ipv6_blocked():
    """::ffff:127.0.0.1 is an IPv4 loopback dressed as IPv6 — must be blocked
    so it cannot bypass the IPv4 SSRF checks."""
    bl = Blocklist()
    assert bl.is_blocked("::ffff:169.254.169.254")[0] is True


def test_cgnat_range_blocked():
    bl = Blocklist()
    assert bl.is_blocked("100.64.0.1")[0] is True


def test_ipv6_multicast_blocked():
    bl = Blocklist()
    assert bl.is_blocked("ff02::1")[0] is True


def test_public_ipv6_allowed():
    bl = Blocklist()
    # 2606:4700:: is Cloudflare / public.
    assert bl.is_blocked("2606:4700::1111")[0] is False


# ---------------------------------------------------------------------------
# Defensive file loading
# ---------------------------------------------------------------------------

def test_corrupt_blocklist_file_is_ignored(tmp_path):
    """A corrupt JSON file must not crash — it is treated as empty and warned."""
    bl_file = tmp_path / "bl.json"
    bl_file.write_text("{ this is not valid json")
    bl = Blocklist(blocklist_path=str(bl_file))
    assert bl.custom_domains == set()


def test_oversized_blocklist_file_is_ignored(tmp_path):
    bl_file = tmp_path / "bl.json"
    bl_file.write_text("x" * (2 * 1024 * 1024))  # 2 MiB > 1 MiB cap
    bl = Blocklist(blocklist_path=str(bl_file))
    assert bl.custom_domains == set()
