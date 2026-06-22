"""Unified Finding model (spec §3.1).

All tools emit Finding objects regardless of their underlying source tool,
so reports/billing/dedup all build on one schema.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FindingType(str, Enum):
    VULNERABILITY = "vulnerability"
    SUBDOMAIN = "subdomain"
    SERVICE = "service"
    EXPOSURE = "exposure"
    INTEL = "intel"
    SECRET_LEAK = "secret_leak"
    OPEN_PORT = "open_port"
    EXPOSED_PATH = "exposed_path"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    # NOTE: Severity also subclasses `str`, which defines rich comparison on
    # the string value. We override all four ordering operators explicitly so
    # ordering reflects severity rank (info < low < ... < critical), not the
    # lexicographic string order ("critical" < "high" < ... would be wrong).

    def __lt__(self, other: "Severity") -> bool:
        return _SEVERITY_RANK[self] < _SEVERITY_RANK[other]

    def __le__(self, other: "Severity") -> bool:
        return _SEVERITY_RANK[self] <= _SEVERITY_RANK[other]

    def __gt__(self, other: "Severity") -> bool:
        return _SEVERITY_RANK[self] > _SEVERITY_RANK[other]

    def __ge__(self, other: "Severity") -> bool:
        return _SEVERITY_RANK[self] >= _SEVERITY_RANK[other]


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass
class Finding:
    id: str
    type: FindingType
    severity: Severity
    target: str
    title: str
    evidence: dict[str, Any] = field(default_factory=dict)
    source_tool: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    timestamp: dt.datetime = field(default_factory=lambda: dt.datetime.now(dt.timezone.utc))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type.value,
            "severity": self.severity.value,
            "target": self.target,
            "title": self.title,
            "evidence": self.evidence,
            "source_tool": self.source_tool,
            "raw": self.raw,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Finding":
        return cls(
            id=d["id"],
            type=FindingType(d["type"]),
            severity=Severity(d["severity"]),
            target=d["target"],
            title=d["title"],
            evidence=d.get("evidence", {}),
            source_tool=d.get("source_tool", ""),
            raw=d.get("raw", {}),
            timestamp=dt.datetime.fromisoformat(d["timestamp"]),
        )

    @staticmethod
    def summary(findings: list["Finding"]) -> dict[str, Any]:
        sev = Counter(f.severity.value for f in findings)
        typ = Counter(f.type.value for f in findings)
        return {
            "total": len(findings),
            "by_severity": dict(sev),
            "by_type": dict(typ),
        }
