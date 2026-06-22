"""
Real-target integration test for SecAgent tools.

Tests each tool against authorized test targets (Acunetix test sites,
Google Firing Range, httpbin.org). These are explicitly designed for
security tool testing.

Usage:
    python3 tests/test_real_targets.py

Environment:
    SECAGENT_BINARIES_DIR  - binary directory (default: ./bin)
    SECAGENT_WORDLISTS_DIR - wordlist directory (default: ./wordlists)
"""
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

# Ensure the project root is in path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Test targets (all are public test sites designed for security scanning)
TEST_TARGETS = {
    "testphp": "testphp.vulnweb.com",
    "testasp": "testasp.vulnweb.com",
    "httpbin": "httpbin.org",
    "firing_range": "public-firing-range.appspot.com",
}

# =========================================================================
# Helper: set up auth + gate
# =========================================================================

def setup_gate_and_token(scope_domain: str):
    from secagent.storage.sqlite_store import SQLiteStore
    from secagent.core.registry import AuthorizationRegistry
    from secagent.core.authz import AuthorizationScope, ScopeType
    from secagent.core.gate import ComplianceGate

    store = SQLiteStore("./data/test_scanning.db")
    store.bootstrap()
    reg = AuthorizationRegistry(store, default_quota=500)
    token = reg.issue(scope=AuthorizationScope(ScopeType.DOMAIN, scope_domain))
    reg.mark_verified(token, method="dns_txt")
    gate = ComplianceGate(store, reg.quota, default_quota=500)
    return gate, token


# =========================================================================
# Tool tests
# =========================================================================

def test_enumerate_subdomains(gate, token, target):
    from secagent.tools.enumerate_subdomains import enumerate_subdomains
    print(f"\n{'='*60}")
    print(f"[enum] enumerate_subdomains on {target}")
    print(f"{'='*60}")
    try:
        result = enumerate_subdomains(
            gate=gate, params={"target_domain": target},
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        print(f"  -> found {len(findings)} subdomains")
        for f in findings[:10]:
            print(f"     {f['target']}")
        if len(findings) > 10:
            print(f"     ... and {len(findings)-10} more")
        return result
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return {"findings": [], "error": str(e)}


def test_scan_ports(gate, token, target):
    from secagent.tools.scan_ports import scan_ports
    print(f"\n{'='*60}")
    print(f"[port] scan_ports on {target}")
    print(f"{'='*60}")
    try:
        result = scan_ports(
            gate=gate, params={"target": target, "ports": "80,443,8080", "rate": 100},
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        print(f"  -> found {len(findings)} open ports")
        for f in findings:
            ev = f.get("evidence", {})
            print(f"     Port {ev.get('port')}/{ev.get('protocol')} - {ev.get('service', 'unknown')}")
        return result
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return {"findings": [], "error": str(e)}


def test_probe_services(gate, token, targets):
    from secagent.tools.probe_services import probe_services
    print(f"\n{'='*60}")
    print(f"[probe] probe_services on {len(targets)} targets")
    print(f"{'='*60}")
    try:
        result = probe_services(
            gate=gate, params={"targets": targets},
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        print(f"  -> found {len(findings)} live services")
        for f in findings[:10]:
            ev = f.get("evidence", {})
            tech = ev.get("tech_stack", [])
            title = f.get("title", "")
            print(f"     {title} tech={tech}")
        if len(findings) > 10:
            print(f"     ... and {len(findings)-10} more")
        return result
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return {"findings": [], "error": str(e)}


def test_discover_paths(gate, token, target_url):
    from secagent.tools.discover_paths import discover_paths
    print(f"\n{'='*60}")
    print(f"[path] discover_paths on {target_url}")
    print(f"{'='*60}")
    try:
        result = discover_paths(
            gate=gate,
            params={"target": f"{target_url}/FUZZ", "rate": 50, "max_time": 30},
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        print(f"  -> discovered {len(findings)} paths/endpoints")
        # Group by severity
        by_sev = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_sev.setdefault(sev, []).append(f)
        for sev in ("critical", "high", "medium", "low", "info"):
            if sev in by_sev:
                print(f"     [{sev}] {len(by_sev[sev])} findings:")
                for f in by_sev[sev][:5]:
                    print(f"       {f['target']} ({f['title'][:100]})")
        return result
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return {"findings": [], "error": str(e)}


def test_scan_vulnerabilities(gate, token, targets):
    from secagent.tools.scan_vulnerabilities import scan_vulnerabilities
    print(f"\n{'='*60}")
    print(f"[vuln] scan_vulnerabilities (nuclei) on {len(targets)} targets")
    print(f"{'='*60}")
    try:
        result = scan_vulnerabilities(
            gate=gate,
            params={
                "targets": targets,
                "severity_filter": "medium",
                "rate_limit": 50,
                "timeout_sec": 120,
            },
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        print(f"  -> found {len(findings)} vulnerabilities")
        for f in findings:
            sev = f.get("severity", "?")
            title = f.get("title", "?")
            target = f.get("target", "?")
            print(f"     [{sev}] {title} @ {target}")
        return result
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return {"findings": [], "error": str(e)}


def test_passive_recon(gate, token, target):
    from secagent.tools.passive_recon import passive_recon
    print(f"\n{'='*60}")
    print(f"[osint] passive_recon on {target}")
    print(f"{'='*60}")
    try:
        result = passive_recon(
            gate=gate, params={"target": target, "sources": ["crtsh"]},
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        print(f"  -> found {len(findings)} OSINT findings")
        for f in findings[:15]:
            print(f"     {f['target']} ({f.get('title', '')[:80]})")
        if len(findings) > 15:
            print(f"     ... and {len(findings)-15} more")
        return result
    except Exception as e:
        print(f"  -> FAILED: {e}")
        return {"findings": [], "error": str(e)}


def test_attack_surface_scan_full(gate, token, target):
    from secagent.tools.attack_surface_scan import attack_surface_scan
    print(f"\n{'='*60}")
    print(f"[chain] attack_surface_scan FULL CHAIN on {target}")
    print(f"{'='*60}")
    try:
        result = attack_surface_scan(
            gate=gate,
            params={
                "target_domain": target,
                "skip_port_scan": False,
                "skip_path_fuzz": False,
                "severity_filter": "low",
                "max_scan_targets": 5,
                "wordlist": "builtin",
            },
            authz_token=token, caller_id="test"
        )
        findings = result.get("findings", [])
        phases = result.get("phases", {})
        print(f"  Total findings: {len(findings)}")
        for phase_name, phase_result in phases.items():
            count = len(phase_result.get("findings", []))
            status = phase_result.get("skipped", "ok")
            print(f"     {phase_name}: {count} findings ({status})")
        # Show top findings by severity
        by_sev = {}
        for f in findings:
            sev = f.get("severity", "info")
            by_sev.setdefault(sev, []).append(f)
        for sev in ("critical", "high", "medium", "low"):
            if sev in by_sev:
                print(f"\n  [{sev}] findings:")
                for f in by_sev[sev][:8]:
                    print(f"     {f['target']} - {f.get('title', '')[:100]}")
        return result
    except Exception as e:
        import traceback
        print(f"  -> FAILED: {e}")
        traceback.print_exc()
        return {"findings": [], "error": str(e)}


# =========================================================================
# Main runner
# =========================================================================

def run_all_tests():
    all_results = {}
    errors = []

    for name, domain in TEST_TARGETS.items():
        print(f"\n\n{'#'*70}")
        print(f"# Testing against: {domain} ({name})")
        print(f"{'#'*70}")

        gate, token = setup_gate_and_token(domain)
        target_results = {}

        # === Tool 1: enumerate_subdomains ===
        target_results["enumerate_subdomains"] = test_enumerate_subdomains(gate, token, domain)

        # === Tool 2: scan_ports ===
        target_results["scan_ports"] = test_scan_ports(gate, token, domain)

        # === Tool 3: probe_services on discovered targets ===
        enum_findings = target_results["enumerate_subdomains"].get("findings", [])
        probe_targets = [domain] + [f.get("target", "") for f in enum_findings if f.get("target")]
        probe_targets = list(dict.fromkeys(probe_targets))[:5]  # dedup, limit
        target_results["probe_services"] = test_probe_services(gate, token, probe_targets)

        # === Tool 4: discover_paths ===
        # Use the base domain with https://
        target_results["discover_paths"] = test_discover_paths(gate, token, f"https://{domain}")

        # === Tool 5: scan_vulnerabilities ===
        probe_findings = target_results["probe_services"].get("findings", [])
        from secagent.tools.attack_surface_scan import _service_scan_target
        vuln_targets = []
        for f in probe_findings:
            url = _service_scan_target(f)
            if url:
                vuln_targets.append(url)
        vuln_targets = list(dict.fromkeys(vuln_targets))[:3]  # limit to 3
        if vuln_targets:
            target_results["scan_vulnerabilities"] = test_scan_vulnerabilities(gate, token, vuln_targets)
        else:
            target_results["scan_vulnerabilities"] = {"findings": [], "note": "no live services"}

        # === Tool 6: passive_recon ===
        target_results["passive_recon"] = test_passive_recon(gate, token, domain)

        # === Tool 7: attack_surface_scan FULL CHAIN ===
        target_results["attack_surface_scan"] = test_attack_surface_scan_full(gate, token, domain)

        all_results[name] = target_results

    return all_results


if __name__ == "__main__":
    print("SecAgent - REAL TARGET INTEGRATION TEST")
    print(f"Targets: {list(TEST_TARGETS.values())}")
    print(f"Time:    {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"CWD:     {os.getcwd()}")

    results = run_all_tests()

    # Save results
    out_path = "./tests/test_real_targets_results.json"
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n\nResults saved to {out_path}")
    print("Done!")
