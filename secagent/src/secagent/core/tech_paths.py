"""Tech-stack-aware path discovery mappings.

Maps technology names (as detected by httpx) to additional path patterns
relevant to that technology. Used by discover_paths to select a more
targeted wordlist based on the detected tech stack.

Each entry maps a technology keyword (lowercase) to a list of extra paths.
The keyword is matched against the `tech_stack` list from probe findings.
"""
from __future__ import annotations

# Common paths per technology. The key is a keyword matched (case-insensitive)
# against the tech_stack list from httpx findings.
_TECH_PATHS: dict[str, list[str]] = {
    # WordPress
    "wordpress": [
        "wp-admin/", "wp-admin/admin-ajax.php", "wp-content/", "wp-content/uploads/",
        "wp-content/plugins/", "wp-content/themes/", "wp-includes/", "wp-login.php",
        "wp-config.php", "wp-config.php.bak", "xmlrpc.php", "wp-json/",
        "wp-json/wp/v2/users", "wp-cron.php", "wp-activate.php", "wp-signup.php",
        "readme.html", "license.txt", "wp-content/debug.log",
    ],
    "drupal": [
        "user/", "user/login", "node/", "sites/", "sites/default/", "sites/default/files/",
        "sites/default/settings.php", "modules/", "themes/", "profiles/", "includes/",
        "misc/", "CHANGELOG.txt", "INSTALL.txt", "README.txt", "robots.txt",
    ],
    "joomla": [
        "administrator/", "components/", "modules/", "plugins/", "templates/",
        "includes/", "language/", "libraries/", "cache/", "tmp/", "logs/",
        "images/", "media/", "README.txt", "htaccess.txt", "configuration.php",
    ],
    "laravel": [
        "artisan", "storage/", "storage/logs/", "storage/framework/", "vendor/",
        ".env", ".env.example", "public/", "resources/", "routes/",
    ],
    "django": [
        "admin/", "static/", "media/", "robots.txt", "sitemap.xml",
        "manage.py", "settings.py", "urls.py", "views.py", "migrations/",
    ],
    "rails": [
        "assets/", "public/", "public/uploads/", "public/robots.txt",
        "Gemfile", "Gemfile.lock", ".env", "config/", "db/",
    ],
    "spring": [
        "actuator/", "actuator/health", "actuator/info", "actuator/env",
        "actuator/beans", "actuator/metrics", "actuator/mappings",
        "actuator/httptrace", "actuator/configprops", "actuator/heapdump",
        "swagger-ui.html", "swagger-ui/", "v2/api-docs", "v3/api-docs",
    ],
    "nginx": [
        "nginx-status", "nginx-status/", "health", "health/",
    ],
    "apache": [
        "server-status", "server-status/", "server-info", "server-info/",
    ],
    "iis": [
        "aspnet_client/", "admin/", "admin.microsoft.com", "remote/",
        "_vti_bin/", "_vti_inf.html", "appsettings.json", "web.config",
    ],
    "tomcat": [
        "manager/", "manager/html", "host-manager/", "examples/",
        "docs/", "servlets-examples/", "jsp-examples/",
    ],
    "jenkins": [
        "jenkins/", "jenkins/api", "jenkins/login", "script",
    ],
    "phpmyadmin": [
        "phpmyadmin/", "phpMyAdmin/", "pma/", "sqladmin/", "adminer/", "adminer.php",
    ],
    "php": [
        "phpinfo.php", "info.php", "test.php", "info/",
    ],
    "react": [
        "static/", "static/js/", "static/css/", "service-worker.js",
        "manifest.json", "asset-manifest.json",
    ],
    "vue": [
        "static/", "js/", "css/", "favicon.ico", "index.html",
    ],
    "flask": [
        ".env", "config.py", "requirements.txt", "static/", "templates/",
    ],
    "express": [
        "package.json", ".env", "routes/", "views/", "public/",
    ],
    "graphql": [
        "graphql", "graphql/", "graphql/console", "graphiql", "graphiql/",
        "v1/graphql", "api/graphql",
    ],
    "swagger": [
        "swagger", "swagger/", "swagger-ui", "swagger-ui/",
        "swagger.json", "swagger.yaml", "swagger.yml",
        "api-docs", "api-docs/", "openapi.json",
    ],
}


def paths_for_tech(tech_stack: list[str] | None) -> list[str]:
    """Return additional discovery paths relevant to the given tech stack.

    Args:
        tech_stack: List of technology names from httpx findings (e.g.
                    ['WordPress', 'PHP', 'nginx']).

    Returns:
        List of additional path strings to include in fuzzing.
    """
    if not tech_stack:
        return []

    matched: set[str] = set()
    tech_lower = [t.lower() for t in tech_stack]
    seen_keywords: set[str] = set()

    for keyword, paths in _TECH_PATHS.items():
        if any(keyword in t for t in tech_lower):
            if keyword not in seen_keywords:
                seen_keywords.add(keyword)
                matched.update(paths)

    return sorted(matched)


def known_tech_keywords() -> list[str]:
    """Return all known technology keywords."""
    return sorted(_TECH_PATHS.keys())
