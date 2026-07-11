"""CLI Reverser — analyze AI CLI tools (Codex/Claude Code/Copilot).

Detects region locking, API authentication mechanisms, local environment
fingerprinting, and binary analysis techniques used by AI CLI tools.

Features:
  - Install script analysis (region detection, auth patterns)
  - Environment fingerprint detection (locale, timezone, fonts, keymap)
  - Token format analysis (JWT, OAuth2, PAT, custom formats)
  - Binary packaging analysis (Rust vs Node.js, obfuscation level)
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

# ── Region detection patterns ──
_REGION_PATTERNS = [
    (re.compile(r"(?:china|cn|mainland|beijing|shanghai)", re.I), "CN-blocked"),
    (re.compile(r"(?:geoblock|geo-block|geo_restrict|region_restrict)", re.I), "Geo-restricted"),
    (re.compile(r"(?:us_only|us_citizen|export_control|sanctions)", re.I), "Export-controlled"),
    (re.compile(r"(?:locale|LC_ALL|LANG|language)", re.I), "Locale-aware"),
]


@dataclass
class InstallScriptAnalysis:
    has_region_detection: bool = False
    region_hints: list[str] = field(default_factory=list)
    auth_mechanisms: list[str] = field(default_factory=list)
    suspicious_patterns: list[str] = field(default_factory=list)


def analyze_install_script(content: str) -> InstallScriptAnalysis:
    """Analyze an install script for region detection and auth patterns."""
    result = InstallScriptAnalysis()

    for pattern, hint in _REGION_PATTERNS:
        if pattern.search(content):
            result.has_region_detection = True
            result.region_hints.append(hint)

    # Auth token patterns
    if re.search(r"(?:export\s+(?:API_KEY|AUTH_TOKEN|PAT)\s*=)", content):
        result.auth_mechanisms.append("env-var-token")
    if re.search(r"(?:login|auth|authenticate|oauth)", content, re.I):
        result.auth_mechanisms.append("oauth-browser-flow")
    if re.search(r"(?:keychain|credential_manager|secrets)", content, re.I):
        result.auth_mechanisms.append("os-keychain")

    # Suspicious patterns
    if re.search(r"(?:eval\s*\(|exec\s*\(|base64\s.*-d)", content):
        result.suspicious_patterns.append("obfuscated-installer")
    if re.search(r"(?:curl.*\|.*bash|curl.*\|.*sh)", content):
        result.suspicious_patterns.append("pipe-to-shell")

    return result


# ── Environment fingerprint detection ──

@dataclass
class EnvironmentFingerprint:
    fingerprint_fields: list[str] = field(default_factory=list)
    detection_method: str = "unknown"  # "env-scan" | "binary-probe" | "API-query"
    evasion_possible: bool = True


_ENV_FINGERPRINT_FIELDS = [
    ("locale", ["LC_ALL", "LANG", "locale", "locale-gen"]),
    ("timezone", ["TZ", "timezone", "localtime", "/etc/timezone"]),
    ("fonts", ["font", "fc-list", "fc-cache", "fontconfig"]),
    ("keymap", ["xkb", "keyboard", "keymap", "localectl"]),
    ("installed_bins", ["which", "command -v", "type ", "hash "]),
]


def detect_fingerprint_fields(content: str) -> EnvironmentFingerprint:
    """Detect which environment fields a CLI tool probes."""
    result = EnvironmentFingerprint()
    found_methods: set[str] = set()

    for env_field, keywords in _ENV_FINGERPRINT_FIELDS:
        for kw in keywords:
            if kw.lower() in content.lower():
                if env_field not in result.fingerprint_fields:
                    result.fingerprint_fields.append(env_field)
                break

    if re.search(r"(?:subprocess\.|popen\(|\.run\(\[)", content):
        found_methods.add("env-scan")
    if re.search(r"(?:/proc/|/sys/|uname|sysctl)", content):
        found_methods.add("binary-probe")
    if re.search(r"(?:https?://.*/(?:geo|region|locale|ping))", content):
        found_methods.add("API-query")

    result.detection_method = ", ".join(found_methods) if found_methods else "none-detected"
    result.evasion_possible = len(result.fingerprint_fields) > 0
    return result


# ── Token format analysis ──

@dataclass
class TokenAnalysis:
    token_format: str = "unknown"          # "JWT" | "OAuth2" | "PAT" | "custom"
    prefix: str = ""
    header_claims: dict[str, Any] = field(default_factory=dict)
    payload_claims: dict[str, Any] = field(default_factory=dict)
    entropy_bits: float = 0.0
    security_issues: list[str] = field(default_factory=list)


_PAT_PATTERNS: list[tuple[str, str]] = [
    (r"^at-", "Anthropic PAT (at- prefix)"),
    (r"^sk-", "OpenAI API Key (sk- prefix)"),
    (r"^ghp_", "GitHub PAT Classic (ghp_ prefix)"),
    (r"^github_pat_", "GitHub PAT Fine-grained (github_pat_ prefix)"),
]


def analyze_token(token: str) -> TokenAnalysis:
    """Analyze a token/credential string to identify its format and security properties."""
    result = TokenAnalysis()

    # Detect PAT format by prefix
    for pattern, desc in _PAT_PATTERNS:
        if re.match(pattern, token):
            result.token_format = "PAT"
            result.prefix = token.split("-")[0] if "-" in token else token[:3]
            result.security_issues.append(f"PAT format detected: {desc}")
            break

    if result.token_format == "unknown":
        parts = token.split(".")
        if len(parts) == 3:
            result.token_format = "JWT"
            try:
                import base64
                import json
                def _b64decode(s: str) -> dict:
                    s += "=" * (4 - len(s) % 4)
                    try:
                        return json.loads(base64.urlsafe_b64decode(s).decode())
                    except Exception:
                        return {}
                result.header_claims = _b64decode(parts[0])
                result.payload_claims = _b64decode(parts[1])
                if result.payload_claims.get("exp"):
                    exp = int(result.payload_claims["exp"])
                    if exp < time.time():
                        result.security_issues.append("JWT expired")
            except Exception:
                pass
        elif len(token) < 40:
            result.token_format = "short-token"
            result.security_issues.append("Short token — may have low entropy")
        else:
            result.token_format = "opaque-token"

    # Entropy estimation
    charset = len(set(token))
    length = len(token)
    if length > 0:
        result.entropy_bits = length * (charset.bit_length() if charset > 1 else 0)
    if result.entropy_bits < 128 and result.token_format != "PAT":
        result.security_issues.append(f"Low entropy: {result.entropy_bits:.0f} bits (<128 recommended)")

    return result


# ── Binary packaging analysis ──

@dataclass
class BinaryAnalysis:
    language: str = "unknown"              # "Rust" | "Node.js" | "Go" | "Python"
    packaging: str = "unknown"             # "npm" | "pip" | "static-binary" | "GitHub Releases"
    obfuscation_level: str = "none"        # "none" | "minified" | "obfuscated" | "compiled"
    reverse_difficulty: str = "medium"     # "easy" | "medium" | "hard" | "extreme"


def analyze_binary_packaging(
    npm_package: dict | None = None,
    binary_path: str | None = None,
    install_script: str | None = None,
) -> BinaryAnalysis:
    """Determine how a CLI tool is packaged and its reverse difficulty."""
    result = BinaryAnalysis()

    if install_script:
        text = install_script.lower()
        if "npm install" in text or "npx " in text:
            result.packaging = "npm"
            result.language = "Node.js (wrapper) → Rust (binary)"
            result.reverse_difficulty = "medium"  # JS wrapper auditable, Rust binary harder
            result.obfuscation_level = "minified" if "minified" in text else "compiled"
        elif "pip install" in text or "setup.py" in text:
            result.packaging = "pip"
            result.language = "Python"
            result.reverse_difficulty = "easy"
            result.obfuscation_level = "none"
        elif re.search(r"(?:curl.*releases|download_url|asset_url)", text):
            result.packaging = "GitHub Releases"
            result.language = "Rust/Go (static binary)"
            result.reverse_difficulty = "hard"
            result.obfuscation_level = "compiled"
        elif "brew install" in text:
            result.packaging = "Homebrew"
            result.language = "Rust/Go (static binary)"
            result.reverse_difficulty = "hard"

    if binary_path and os.path.exists(binary_path):
        try:
            r = subprocess.run(["file", binary_path], capture_output=True, text=True, timeout=5)
            out = r.stdout.lower()
            if "mach-o" in out:
                result.language = "Rust/Go/C++ (native macOS binary)"
                result.reverse_difficulty = "hard"
            elif "elf" in out:
                result.language = "Rust/Go/C++ (native ELF binary)"
                result.reverse_difficulty = "hard"
            elif "node" in out or "javascript" in out:
                result.language = "Node.js"
                result.reverse_difficulty = "easy"
        except Exception:
            pass

    return result


# ── CLI Reverse summary ──

@dataclass
class CLIReverseReport:
    name: str
    version: str = "unknown"
    region_detection: InstallScriptAnalysis | None = None
    env_fingerprint: EnvironmentFingerprint | None = None
    token: TokenAnalysis | None = None
    binary: BinaryAnalysis | None = None
    detection_layers: list[str] = field(default_factory=list)
    evasion_suggestions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name, "version": self.version,
            "region_detection": {
                "detected": self.region_detection.has_region_detection if self.region_detection else False,
                "hints": self.region_detection.region_hints if self.region_detection else [],
                "auth": self.region_detection.auth_mechanisms if self.region_detection else [],
                "suspicious": self.region_detection.suspicious_patterns if self.region_detection else [],
            },
            "env_fingerprint": {
                "fields": self.env_fingerprint.fingerprint_fields if self.env_fingerprint else [],
                "method": self.env_fingerprint.detection_method if self.env_fingerprint else "",
            },
            "token": {
                "format": self.token.token_format if self.token else "unknown",
                "prefix": self.token.prefix if self.token else "",
                "entropy_bits": self.token.entropy_bits if self.token else 0,
                "issues": self.token.security_issues if self.token else [],
            },
            "binary": {
                "language": self.binary.language if self.binary else "unknown",
                "packaging": self.binary.packaging if self.binary else "unknown",
                "obfuscation": self.binary.obfuscation_level if self.binary else "none",
                "difficulty": self.binary.reverse_difficulty if self.binary else "unknown",
            },
            "detection_layers": self.detection_layers,
            "evasion_suggestions": self.evasion_suggestions,
        }
