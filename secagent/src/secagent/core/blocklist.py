"""Defense line 2 — compliance blocklist (spec §4.2).

Even with authorization, some targets are never scanned:
government/military TLDs, known CII, and private/internal IPs (SSRF guard).
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path
from typing import Optional

from secagent.core.errors import ComplianceBlockError

GOV_TLDS = (".gov", ".mil", ".gov.cn", ".edu", ".gov.uk", ".gob", ".gov.au", ".gov.br")

# RFC 1918 + loopback + link-local (cloud metadata 169.254.169.254 lives here)
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


class Blocklist:
    def __init__(self, blocklist_path: str | None = None):
        self.custom_domains: set[str] = set()
        if blocklist_path and Path(blocklist_path).exists():
            data = json.loads(Path(blocklist_path).read_text(encoding="utf-8"))
            self.custom_domains = {d.lower() for d in data.get("domains", [])}

    def is_blocked(self, target: str) -> tuple[bool, Optional[str]]:
        """Return (blocked, reason). reason is None if not blocked."""
        t = target.strip().lower()
        # custom domain list
        if t in self.custom_domains:
            return True, "in custom blocklist"
        # government / military TLDs
        for tld in GOV_TLDS:
            if t.endswith(tld):
                return True, f"government/infrastructure TLD ({tld})"
        # IP-based checks
        try:
            ip = ipaddress.ip_address(t)
            for net in PRIVATE_NETWORKS:
                if ip in net:
                    return True, f"private/reserved IP range ({net})"
        except ValueError:
            pass  # not an IP literal — fine
        return False, None

    def check(self, target: str) -> None:
        """Raise ComplianceBlockError if target is blocked."""
        blocked, reason = self.is_blocked(target)
        if blocked:
            raise ComplianceBlockError(target=target, reason=reason or "blocklist match")
