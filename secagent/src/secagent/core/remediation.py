"""Remediation knowledge base — maps findings to actionable fix suggestions.

Absorbed from Strix's "actionable findings with remediation guidance" pattern.
Each rule is a (title_pattern, severity, advice) tuple.

CURRENT RULE COUNT: 44 rules across Critical/High/Medium/Low severities.
Covers: credential leaks, infrastructure exposure (Redis/MongoDB/K8s/Docker),
Web vulns (SQLi/XSS/SSRF/Subdomain Takeover), TLS/certs, headers, misconfig.
"""
from __future__ import annotations

import re
from typing import Any

_REMEDIATIONS: list[tuple[re.Pattern, str, str]] = [
    # ========== CRITICAL: 凭证 / 核心数据泄漏 ==========
    (re.compile(r"\.git/config|\.git/HEAD", re.I),
     "critical", "Remove `.git/` directory from production web root. "
     "Configure your web server (nginx/apache) to deny access to dot-files: "
     "`location ~ /\\. { deny all; }`"),
    (re.compile(r"\.env", re.I),
     "critical", "Remove `.env` file from public web root. "
     "Store secrets in environment variables or a vault (HashiCorp Vault, AWS Secrets Manager). "
     "Add `*.env` to `.gitignore` and scrub from git history with `git filter-branch`."),
    (re.compile(r"credentials|\.aws/credentials", re.I),
     "critical", "Remove credential files from web-accessible directories. "
     "Rotate any exposed keys/tokens immediately. Use a secrets manager instead."),
    (re.compile(r"id_rsa|\.ssh/id_rsa|\.id_dsa|\.id_ed25519", re.I),
     "critical", "Remove SSH private keys from any web-accessible directory. "
     "Revoke the key on all servers where it was authorized. "
     "Generate a new key pair and audit for unauthorized access."),
    (re.compile(r"\.sql_dump|\.sql\.gz|\.sql\.bz2|backup\.sql|database\.sql", re.I),
     "critical", "Remove SQL dump files from production web root immediately. "
     "Assume all data in the dump is compromised — force-reset affected user passwords "
     "and API keys. Add `*.sql`, `*.dump`, `*.backup` to your web server deny list."),
    (re.compile(r"\.svn/entries|\.hg/dirstate|\.bzr/", re.I),
     "critical", "Remove revision control metadata directories from production web root. "
     "Configure your web server to deny access to `.svn/`, `.hg/`, `.bzr/` directories: "
     r"`location ~ /\.(svn|hg|bzr) { deny all; }`"),

    # ========== CRITICAL: 高危基础设施暴露 ==========
    (re.compile(r"redis|6379", re.I),
     "critical", "Bind Redis to localhost only (add `bind 127.0.0.1` to redis.conf) "
     "or place behind a firewall with ACL. Enable Redis AUTH (`requirepass`). "
     "Do NOT expose Redis directly to the internet — it exposes OS-level command access."),
    (re.compile(r"mongodb|27017", re.I),
     "critical", "Bind MongoDB to localhost only and enable authentication. "
     "Use a firewall to restrict access. Verify no data has been deleted or ransomed."),
    (re.compile(r"elasticsearch|9200", re.I),
     "critical", "Enable X-Pack security with TLS and authentication for Elasticsearch. "
     "Restrict port 9200 to internal network only. Data at index `_all` may be exposable."),
    (re.compile(r"docker.*socket|docker.*api|/var/run/docker\.sock", re.I),
     "critical", "Remove Docker socket from web-accessible paths. "
     "If Docker API is exposed, consider the host fully compromised — "
     "an attacker can escalate to root via container escape."),
    (re.compile(r"kubernetes|8443|6443", re.I),
     "critical", "Restrict Kubernetes API server access to internal network. "
     "Enable RBAC with least-privilege. Review for unauthorized pod creation."),

    # ========== CRITICAL: 特定知名 CVE 修复建议 ==========
    (re.compile(r"cve.2021.44228|log4shell|jndi", re.I),
     "critical", "Immediately update Log4j to version 2.3.2+ or 2.17.1+ (best). "
     "Temporary mitigations: set `LOG4J_FORMAT_MSG_NO_LOOKUPS=true` or remove "
     "`JndiLookup` class: `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class`"),
    (re.compile(r"shellshock|cve.2014.6271|cve.2014.7169", re.I),
     "critical", "Immediately patch Bash to the latest version (compat -4.3 patch 30+). "
     "If Bash cannot be updated, replace CGI scripts with compiled binaries or disable CGI entirely."),

    # ========== HIGH ==========
    (re.compile(r"exposed.*admin|admin.*panel|wp-admin|phpmyadmin", re.I),
     "high", "Restrict admin panel access by IP whitelist or VPN. "
     "Add HTTP basic auth as a second layer. "
     "nginx: `location /admin { allow YOUR_IP; deny all; auth_basic ...; }`"),
    (re.compile(r"CVE-\d{4}-\d{4,}", re.I),
     "high", "Update the affected component to the latest patched version. "
     "If an immediate update is not possible, apply virtual patching via WAF rules. "
     "Monitor the CVE entry for updated remediation guidance."),
    (re.compile(r"open.*redirect|url.*redirect|remote.*redirect", re.I),
     "high", "Validate and whitelist redirect targets. "
     "Do not accept arbitrary `url`, `next`, `return`, `redirect_url` parameters. "
     "Use a mapping of allowed redirect destinations instead. "
     "Implement an allowlist of trusted relative paths."),
    (re.compile(r"SQL.*Injection|sqli", re.I),
     "high", "Use parameterized queries (prepared statements) instead of string concatenation. "
     "Apply input validation and an ORM layer. WAF rules can provide temporary protection. "
     "Example: `cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))`"),
    (re.compile(r"XSS|Cross.?Site.?Scripting|html.*injection", re.I),
     "high", "Apply context-aware output encoding. "
     "Set Content-Security-Policy header: `script-src 'self'`. "
     "Use DOMPurify for user-generated HTML. Sanitize all inputs. "
     "In React/Vue, use `{{variable}}` auto-escaping instead of `v-html`/`dangerouslySetInnerHTML`."),
    (re.compile(r"SSRF|Server.?Side.?Request.?Forgery", re.I),
     "high", "Validate and whitelist all outbound URL targets. "
     "Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16). "
     "Disable unused URL schemas in HTTP clients (file://, dict://, gopher://). "
     "Apply network segmentation for the service making outbound calls."),
    (re.compile(r"subdomain.*takeover|sub.?takeover|unclaimed.*subdomain|cname.*unregistered", re.I),
     "high", "Subdomain takeover is in progress or possible. "
     "If the third-party service claim is expired, immediately re-register it. "
     "Then remove the DNS CNAME/NS record pointing to the unclaimed service. "
     "Verify that the subdomain is no longer resolvable to the third-party service."),
    (re.compile(r"default.*credentials?|default.*password|admin.*admin|admin.*123456", re.I),
     "high", "Change default credentials immediately on all affected services. "
     "Implement a password policy requiring strong, unique passwords. "
     "Disable default accounts if possible and create named admin accounts with audit trail."),

    # ========== MEDIUM ==========
    (re.compile(r"swagger|api.*doc|openapi", re.I),
     "medium", "Restrict API documentation access in production. "
     "Disable Swagger UI when not needed: set `springdoc.api-docs.enabled=false` "
     "or remove `swagger-ui` from dependencies."),
    (re.compile(r"actuator|spring.*actuator", re.I),
     "medium", "Restrict Spring Actuator endpoints to internal network only. "
     "Set `management.endpoints.web.exposure.include=health,info` in production. "
     "Do not expose `/actuator/env`, `/actuator/beans`, `/actuator/heapdump` publicly."),
    (re.compile(r"phpinfo|info\.php", re.I),
     "medium", "Remove `info.php` / `phpinfo()` from production servers. "
     "This file leaks PHP configuration, loaded modules, and environment variables."),
    (re.compile(r"debug|debug.*mode|traceback|stacktrace", re.I),
     "medium", "Disable debug mode in production. "
     "Set `APP_DEBUG=false`, `DJANGO_DEBUG=False`, `NODE_ENV=production`. "
     "Disable framework debug pages that leak source code, SQL queries, and env variables."),
    (re.compile(r"CORS|access.control.allow", re.I),
     "medium", "Restrict CORS to trusted origins only. "
     "Do not use `Access-Control-Allow-Origin: *` with credentials. "
     "Do not reflect arbitrary origins from the `Origin` header. "
     "Maintain an allowlist of exact origins and validate against it."),
    (re.compile(r"directory.*listing|autoindex|index.of", re.I),
     "medium", "Disable directory listing in production web server config. "
     "nginx: `autoindex off;`  Apache: `Options -Indexes`"),
    (re.compile(r"backup|\.bak|\.zip|\.tar\.gz|\.tgz|\.old|\.swp", re.I),
     "medium", "Remove backup, swap, and archive files from production web root. "
     "Configure web server to deny access to `*.bak`, `*.old`, `*.swp`, `*.zip`, `*.tar.gz`: "
     r"`location ~* \.(bak|old|swp|zip|tar|gz|tgz)$ { deny all; }`"),
    (re.compile(r"wp.config|wp-config|config\.dist|\.config\.bak", re.I),
     "medium", "Remove or move web framework configuration backups outside web root. "
     "wp-config.php.bak, config.php.bak, etc. can expose database credentials. "
     "Add `*.bak` `*.dist` `*.backup` to web server deny list."),
    (re.compile(r"robots\.txt|security\.txt|sitemap\.xml", re.I),
     "medium", "Review `robots.txt` and `security.txt` for sensitive paths. "
     "Do not rely on robots.txt for security — it is publicly indexed and may aid attackers. "
     "Only use `security.txt` to provide a responsible disclosure contact URL."),
    (re.compile(r"wp-admin|wp-login|xmlrpc|wordpress", re.I),
     "medium", "For WordPress: move wp-admin to a custom path or restrict by IP. "
     "Disable XML-RPC if not needed (`add_filter('xmlrpc_enabled', '__return_false');`). "
     "Apply a Web Application Firewall (Cloudflare, Sucuri) with WordPress-specific rules."),
    (re.compile(r"jenkins|joomla|drupal|tomcat.*manager", re.I),
     "medium", "Restrict access to CMS and CI/CD admin interfaces by IP whitelist. "
     "Keep the software updated to the latest security patch. "
     "Remove default admin accounts and disable unused plugins/modules."),
    (re.compile(r"traefik|rancher|portainer|kubernetes.*dashboard", re.I),
     "medium", "Restrict orchestration and infrastructure management UIs to internal network or VPN. "
     "Enable authentication and enforce role-based access control. "
     "Review for unauthorized containers or deployments."),

    # ========== LOW (信息泄漏 / 安全头) ==========
    (re.compile(r"X.?Frame.?Options|clickjack|frame.?ancestors", re.I),
     "low", "Add `X-Frame-Options: DENY` or `SAMEORIGIN` header. "
     "Alternatively use Content-Security-Policy `frame-ancestors 'self'`."),
    (re.compile(r"HSTS|Strict.?Transport.?Security|max.age", re.I),
     "low", "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` header. "
     "Ensure HTTPS is enforced before enabling HSTS. "
     "Consider adding the domain to the HSTS preload list."),
    (re.compile(r"X.?Content.?Type.?Options|nosniff", re.I),
     "low", "Add `X-Content-Type-Options: nosniff` header to prevent MIME sniffing."),
    (re.compile(r"open.*port.*22|ssh.*exposed", re.I),
     "low", "Restrict SSH access by IP whitelist. Use key-based auth only. "
     "Consider moving SSH to a non-standard port or using a VPN/bastion host. "
     "Set `Protocol 2` and disable password authentication (`PasswordAuthentication no`)."),
    (re.compile(r"Cookie.*missing.*secure|Secure.*flag|httponly|same.?site", re.I),
     "low", "Set `Secure` flag on all cookies when served over HTTPS. "
     "Also set `HttpOnly` for session cookies. Add `SameSite=Lax` or `Strict`. "
     "Session cookies should have all three flags: `Secure; HttpOnly; SameSite=Lax`"),
    (re.compile(r"tls.*expired|certificate.*expired|expired.*certificate|x509.*expired", re.I),
     "low", "Renew the TLS certificate immediately. Expired certs cause browser warnings and MITM vulnerability. "
     "Set up automated renewal with Let's Encrypt (`certbot renew`). "
     "Monitor 30 days before expiry. Reconfigure web server with new certificate."),
    (re.compile(r"tls.*self.?signed", re.I),
     "low", "Replace self-signed certificate with one from a trusted CA (Let's Encrypt, DigiCert). "
     "Self-signed certs expose users to man-in-the-middle attacks. "
     "For internal services, consider an internal CA (HashiCorp Vault PKI)."),
    (re.compile(r"tls.*tls1\.0|tls.*1\.0|ssl3|rc4|weak.*cipher|deprecated.*protocol", re.I),
     "low", "Disable TLS 1.0/1.1 and weak cipher suites (RC4, DES, 3DES, MD5). "
     "Configure to use TLS 1.2 minimum, TLS 1.3 preferred. "
     "Use recommended cipher lists: `ssl_protocols TLSv1.2 TLSv1.3;` (nginx)"),
    (re.compile(r".*X.X.X.X.*outdated|server.*apaches?.*\d\.\d|P.hp\.\d\.\d", re.I),
     "low", "Update the server software (PHP, Apache, Nginx, OpenSSL) to the latest stable release. "
     "Outdated server components may have publicly-known vulnerabilities. "
     "Subscribe to security announcements (e.g., distros-announce, security-tracker.debian.org)"),
    (re.compile(r"email.*spf|email.*dkim|email.*dmarc|spf-record|dkim-record", re.I),
     "low", "Implement SPF, DKIM, and DNS records for email deliverability and spoofing prevention. "
     "Add SPF: `v=spf1 include:_spf.google.com -all`. "
     "Configure DKIM via your email provider. "
     "Add DMARC: `_dmarc TXT 'v=DMARC1; p=reject; rua=mailto:dmarc@example.com'`"),
    (re.compile(r"DNS.*zone.?transfer|allow.transfer.*any|axfr", re.I),
     "low", "Restrict DNS zone transfers to authorized secondary nameservers only. "
     "In named.conf: `allow-transfer { 192.168.1.2; 192.168.1.3; };`"
     "Zone transfer can leak all DNS records, exposing internal infrastructure."),
]

# Pattern-type-specific confidence boosters
_CONFIDENCE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r"200.*\.git/config", re.I), "validated"),
    (re.compile(r"200.*\.env", re.I), "validated"),
    (re.compile(r"401|403", re.I), "likely"),
    (re.compile(r"500|502|503", re.I), "likely"),
]


def remediate(finding_type: str, severity: str, title: str) -> str:
    """Return remediation advice for a finding, or '' if none matches.

    Matches by pattern only — regardless of severity rank (a high-severity
    .git leak gets the same remediation advice as a critical one).
    """
    safe_title = title or ""
    for pattern, sev, advice in _REMEDIATIONS:
        if pattern.search(safe_title):
            return advice
    return ""


def estimate_confidence(severity: str, title: str, status_code: int | None = None) -> str:
    """Estimate confidence for an unvalidated finding."""
    safe_title = f"{status_code} {title}" if status_code else (title or "")
    for pattern, confidence in _CONFIDENCE_RULES:
        if pattern.search(safe_title):
            return confidence
    # Default by severity
    sev_map = {"critical": "validated", "high": "likely",
               "medium": "unvalidated", "low": "unvalidated", "info": "unvalidated"}
    return sev_map.get(severity, "unvalidated")


def enrich_finding(finding_dict: dict[str, Any]) -> dict[str, Any]:
    """Add confidence and remediation to a finding dict in place, returns it."""
    if not finding_dict.get("remediation"):
        advice = remediate(
            finding_dict.get("type", ""),
            finding_dict.get("severity", "info"),
            finding_dict.get("title", ""),
        )
        if advice:
            finding_dict["remediation"] = advice

    if not finding_dict.get("confidence") or finding_dict["confidence"] == "unvalidated":
        evidence = finding_dict.get("evidence", {}) or {}
        status_code = evidence.get("status_code") or evidence.get("status")
        finding_dict["confidence"] = estimate_confidence(
            finding_dict.get("severity", "info"),
            finding_dict.get("title", ""),
            status_code,
        )
    return finding_dict
