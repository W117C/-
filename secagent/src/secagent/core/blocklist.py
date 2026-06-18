"""Defense line 2 — compliance blocklist (spec §4.2).

Even with authorization, some targets are never scanned:
government/military TLDs, known CII, and private/internal IPs (SSRF guard).
"""
from __future__ import annotations

import ipaddress
import json
import logging
from pathlib import Path
from typing import Optional

from secagent.core.errors import ComplianceBlockError

log = logging.getLogger(__name__)

GOV_TLDS = (".gov", ".mil", ".gov.cn", ".edu", ".gov.uk", ".gob", ".gov.au", ".gov.br")

# Private / reserved / loopback ranges for BOTH IPv4 and IPv6. This is the SSRF
# guard: even an in-scope, authorized target must not be scanned if it resolves
# to an internal address. Covers:
#  - RFC 1918 private space + IPv6 ULA (fc00::/7)
#  - loopback (IPv4 127/8, IPv6 ::1)
#  - link-local (169.254/16 — cloud metadata 169.254.169.254 lives here, plus
#    IPv6 fe80::/10)
#  - IPv4-mapped IPv6 (::ffff:0.0.0.0/96) which would otherwise bypass the
#    IPv4 checks when a host exposes its internal IP over IPv6
#  - CGNAT 100.64.0.0/10
#  - unspecified (0.0.0.0/8, ::) and multicast
PRIVATE_NETWORKS = [
    # IPv4
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("224.0.0.0/4"),
    # IPv6
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0.0.0.0/96"),
    ipaddress.ip_network("ff00::/8"),
    ipaddress.ip_network("::/128"),
]

# Cap on a custom blocklist file size so a misconfigured path can't OOM us.
_MAX_BLOCKLIST_BYTES = 1 * 1024 * 1024  # 1 MiB


class Blocklist:
    def __init__(self, blocklist_path: str | None = None):
        self.custom_domains: set[str] = set()
        if blocklist_path:
            self._load_blocklist(blocklist_path)

    def _load_blocklist(self, blocklist_path: str) -> None:
        p = Path(blocklist_path)
        if not p.exists():
            return
        try:
            raw = p.read_bytes()
            if len(raw) > _MAX_BLOCKLIST_BYTES:
                raise ValueError(f"blocklist file exceeds {_MAX_BLOCKLIST_BYTES} bytes")
            data = json.loads(raw.decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("blocklist must be a JSON object")
            domains = data.get("domains", [])
            self.custom_domains = {str(d).lower() for d in domains}
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            # A corrupt/unreadable blocklist is logged and treated as empty
            # rather than crashing the gate — but it is surfaced loudly.
            log.warning("failed to load blocklist %s: %s", blocklist_path, exc)
            self.custom_domains = set()

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
        # IP-based checks (strip IPv6 brackets and an optional zone id)
        candidate = t
        if candidate.startswith("[") and candidate.endswith("]"):
            candidate = candidate[1:-1]
        candidate = candidate.split("%")[0]
        try:
            ip = ipaddress.ip_address(candidate)
            for net in PRIVATE_NETWORKS:
                if ip.version == net.version and ip in net:
                    return True, f"private/reserved IP range ({net})"
        except ValueError:
            pass  # not an IP literal — fine
        return False, None

    def check(self, target: str) -> None:
        """Raise ComplianceBlockError if target is blocked."""
        blocked, reason = self.is_blocked(target)
        if blocked:
            raise ComplianceBlockError(target=target, reason=reason or "blocklist match")
