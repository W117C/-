from __future__ import annotations

import datetime as dt

from secagent.core.finding import Finding, FindingType, Severity


def test_finding_round_trips_to_dict():
    f = Finding(
        id="fnd_001",
        type=FindingType.VULNERABILITY,
        severity=Severity.HIGH,
        target="sub.acme.com",
        title="CVE-2024-XXXX on /api",
        evidence={"template_id": "cve-2024-xxxx", "matched_at": "/api"},
        source_tool="nuclei",
        timestamp=dt.datetime(2026, 6, 16, 10, 0, 0, tzinfo=dt.timezone.utc),
    )
    d = f.to_dict()
    assert d["id"] == "fnd_001"
    assert d["type"] == "vulnerability"
    assert d["severity"] == "high"
    assert d["source_tool"] == "nuclei"
    assert d["timestamp"] == "2026-06-16T10:00:00+00:00"


def test_finding_from_dict_preserves_fields():
    d = {
        "id": "fnd_002",
        "type": "subdomain",
        "severity": "info",
        "target": "blog.acme.com",
        "title": "Discovered subdomain",
        "evidence": {"source": "crtsh"},
        "source_tool": "subfinder",
        "timestamp": "2026-06-16T10:00:00+00:00",
    }
    f = Finding.from_dict(d)
    assert f.type is FindingType.SUBDOMAIN
    assert f.severity is Severity.INFO
    assert f.evidence == {"source": "crtsh"}


def test_severity_ordering():
    assert Severity.CRITICAL > Severity.HIGH > Severity.MEDIUM > Severity.LOW > Severity.INFO


def test_summary_counts_by_severity():
    findings = [
        Finding(id="1", type=FindingType.VULNERABILITY, severity=Severity.HIGH, target="a", title="t", evidence={}, source_tool="n", timestamp=dt.datetime(2026, 6, 16, tzinfo=dt.timezone.utc)),
        Finding(id="2", type=FindingType.VULNERABILITY, severity=Severity.HIGH, target="a", title="t", evidence={}, source_tool="n", timestamp=dt.datetime(2026, 6, 16, tzinfo=dt.timezone.utc)),
        Finding(id="3", type=FindingType.SUBDOMAIN, severity=Severity.INFO, target="a", title="t", evidence={}, source_tool="n", timestamp=dt.datetime(2026, 6, 16, tzinfo=dt.timezone.utc)),
    ]
    s = Finding.summary(findings)
    assert s["total"] == 3
    assert s["by_severity"]["high"] == 2
    assert s["by_severity"]["info"] == 1
    assert s["by_type"]["vulnerability"] == 2
    assert s["by_type"]["subdomain"] == 1
