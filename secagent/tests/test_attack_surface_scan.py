"""Orchestration tests for attack_surface_scan (upgraded chain)."""
from __future__ import annotations

from unittest.mock import patch

import pytest

from secagent.core.errors import InvalidInputError
from secagent.tools.attack_surface_scan import attack_surface_scan


def _finding(
    id_: str,
    type_: str,
    severity: str,
    target: str,
    evidence: dict | None = None,
) -> dict:
    return {
        "id": id_,
        "type": type_,
        "severity": severity,
        "target": target,
        "title": target,
        "evidence": evidence or {},
        "source_tool": "test",
        "raw": {},
        "timestamp": "2026-06-22T00:00:00+00:00",
    }


def _result(tool: str, findings: list[dict], quota_used: int = 1) -> dict:
    return {
        "engagement_id": f"eng_{tool}",
        "tool": tool,
        "findings": findings,
        "summary": {"total": len(findings), "by_severity": {}, "by_type": {}},
        "quota_used": quota_used,
    }


def _empty_result(tool: str) -> dict:
    return _result(tool, [], 0)


def test_attack_surface_scan_chains_enum_probe_and_nuclei():
    enum_finding = _finding(
        "fnd_sub",
        "subdomain",
        "info",
        "api.acme.com",
    )
    service_finding = _finding(
        "fnd_service",
        "service",
        "info",
        "api.acme.com",
        {"protocol": "https", "port": "443"},
    )
    vuln_finding = _finding(
        "fnd_vuln",
        "vulnerability",
        "high",
        "https://api.acme.com",
    )

    captured_probe = {}
    captured_scan = {}

    def fake_probe(*, gate, params, authz_token, caller_id):
        captured_probe["params"] = params
        return _result("probe_services", [service_finding])

    def fake_scan(*, gate, params, authz_token, caller_id):
        captured_scan["params"] = params
        return _result("scan_vulnerabilities", [vuln_finding])

    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", [enum_finding]),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        side_effect=fake_probe,
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
        side_effect=fake_scan,
    ), patch(
        "secagent.tools.scan_ports.scan_ports",
        return_value=_empty_result("scan_ports"),
    ):
        result = attack_surface_scan(
            gate=None,
            params={"target_domain": "acme.com", "templates": ["cves"]},
            authz_token="auth_x",
            caller_id="tester",
        )

    assert captured_probe["params"]["targets"] == ["acme.com", "api.acme.com"]
    assert captured_scan["params"]["targets"] == ["https://api.acme.com"]
    assert captured_scan["params"]["templates"] == ["cves"]
    assert result["summary"]["by_type"] == {
        "subdomain": 1,
        "service": 1,
        "vulnerability": 1,
    }
    assert result["summary"]["by_severity"] == {"info": 2, "high": 1}
    assert result["quota_used"] == 3


def test_attack_surface_scan_adds_non_default_service_port_to_url():
    service_finding = _finding(
        "fnd_service",
        "service",
        "info",
        "admin.acme.com",
        {"protocol": "http", "port": "8080"},
    )
    captured_scan = {}

    def fake_scan(*, gate, params, authz_token, caller_id):
        captured_scan["params"] = params
        return _result("scan_vulnerabilities", [])

    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", []),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        return_value=_result("probe_services", [service_finding]),
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
        side_effect=fake_scan,
    ), patch(
        "secagent.tools.scan_ports.scan_ports",
        return_value=_empty_result("scan_ports"),
    ):
        attack_surface_scan(
            gate=None,
            params={"target_domain": "acme.com"},
            authz_token="auth_x",
            caller_id="tester",
        )

    assert captured_scan["params"]["targets"] == ["http://admin.acme.com:8080"]


def test_attack_surface_scan_skips_nuclei_when_no_live_services():
    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", []),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        return_value=_result("probe_services", []),
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
    ) as mock_scan, patch(
        "secagent.tools.scan_ports.scan_ports",
        return_value=_empty_result("scan_ports"),
    ):
        result = attack_surface_scan(
            gate=None,
            params={"target_domain": "acme.com"},
            authz_token="auth_x",
            caller_id="tester",
        )

    mock_scan.assert_not_called()
    assert result["quota_used"] == 2
    assert result["phases"]["scan_vulnerabilities"]["skipped"] == (
        "no live services discovered"
    )


def test_attack_surface_scan_caps_active_scan_targets():
    services = [
        _finding(
            f"fnd_{i}",
            "service",
            "info",
            f"host{i}.acme.com",
            {"protocol": "https", "port": "443"},
        )
        for i in range(3)
    ]
    captured_scan = {}

    def fake_scan(*, gate, params, authz_token, caller_id):
        captured_scan["params"] = params
        return _result("scan_vulnerabilities", [])

    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", []),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        return_value=_result("probe_services", services),
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
        side_effect=fake_scan,
    ), patch(
        "secagent.tools.scan_ports.scan_ports",
        return_value=_empty_result("scan_ports"),
    ):
        result = attack_surface_scan(
            gate=None,
            params={"target_domain": "acme.com", "max_scan_targets": 2},
            authz_token="auth_x",
            caller_id="tester",
        )

    assert captured_scan["params"]["targets"] == [
        "https://host0.acme.com",
        "https://host1.acme.com",
    ]
    assert result["scan_targets_omitted"] == 1


def test_attack_surface_scan_with_port_scan_phase():
    """Verify port scan phase runs and passes ports to probe."""
    service_finding = _finding(
        "fnd_service",
        "service",
        "info",
        "acme.com",
        {"protocol": "https", "port": "443"},
    )
    port_finding = _finding(
        "fnd_port",
        "open_port",
        "info",
        "acme.com",
        {"port": 443, "protocol": "tcp", "service": "https"},
    )

    captured_probe = {}

    def fake_probe(*, gate, params, authz_token, caller_id):
        captured_probe["params"] = params
        return _result("probe_services", [service_finding])

    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", []),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        side_effect=fake_probe,
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
        return_value=_result("scan_vulnerabilities", []),
    ), patch(
        "secagent.tools.scan_ports.scan_ports",
        return_value=_result("scan_ports", [port_finding]),
    ):
        result = attack_surface_scan(
            gate=None,
            params={"target_domain": "acme.com"},
            authz_token="auth_x",
            caller_id="tester",
        )

    # Port scan should have run and found ports
    assert result["phases"]["scan_ports"]["summary"]["total"] == 1
    # Probe should receive port-restricted targets
    assert "ports" in captured_probe["params"]
    assert "443" in captured_probe["params"]["ports"]


def test_attack_surface_scan_with_path_fuzz():
    """Verify path fuzzing phase runs when enabled."""
    service_finding = _finding(
        "fnd_service",
        "service",
        "info",
        "acme.com",
        {"protocol": "https", "port": "443"},
    )
    path_finding = _finding(
        "fnd_path",
        "exposed_path",
        "high",
        "https://acme.com/admin",
    )

    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", []),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        return_value=_result("probe_services", [service_finding]),
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
        return_value=_result("scan_vulnerabilities", []),
    ), patch(
        "secagent.tools.scan_ports.scan_ports",
        return_value=_empty_result("scan_ports"),
    ), patch(
        "secagent.tools.discover_paths.discover_paths",
        return_value=_result("discover_paths", [path_finding]),
    ):
        result = attack_surface_scan(
            gate=None,
            params={
                "target_domain": "acme.com",
                "skip_path_fuzz": False,
                "wordlist": "builtin",
            },
            authz_token="auth_x",
            caller_id="tester",
        )

    assert result["phases"]["discover_paths"]["summary"]["total"] == 1
    assert result["summary"]["by_type"]["exposed_path"] == 1


def test_attack_surface_scan_validates_target_domain():
    with pytest.raises(InvalidInputError):
        attack_surface_scan(
            gate=None,
            params={},
            authz_token="auth_x",
            caller_id="tester",
        )


def test_attack_surface_scan_skip_port_scan():
    """skip_port_scan=True should skip the port scan phase."""
    with patch(
        "secagent.tools.attack_surface_scan.enumerate_subdomains",
        return_value=_result("enumerate_subdomains", []),
    ), patch(
        "secagent.tools.attack_surface_scan.probe_services",
        return_value=_result("probe_services", []),
    ), patch(
        "secagent.tools.attack_surface_scan.scan_vulnerabilities",
    ) as mock_scan:
        result = attack_surface_scan(
            gate=None,
            params={
                "target_domain": "acme.com",
                "skip_port_scan": True,
            },
            authz_token="auth_x",
            caller_id="tester",
        )

    mock_scan.assert_not_called()
    assert result["phases"]["scan_ports"]["skipped"] == (
        "port scanning disabled"
    )
