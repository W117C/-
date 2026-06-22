"""`secagent authz add|verify|list` — authorization registry CLI (spec §4.1)."""
from __future__ import annotations

import click

from secagent.config import Config
from secagent.core.authz import AuthorizationScope, ScopeType
from secagent.core.registry import AuthorizationRegistry
from secagent.storage.sqlite_store import SQLiteStore


def _registry() -> AuthorizationRegistry:
    cfg = Config.load()
    store = SQLiteStore(cfg.db_path)
    store.bootstrap()
    return AuthorizationRegistry(store, default_quota=cfg.default_quota_per_token)


@click.group()
def authz() -> None:
    """Manage authorization scopes."""


@authz.command("add")
@click.option("--domain", "domain", help="Authorize a domain (incl. subdomains).")
@click.option("--ip", "ip", help="Authorize a single IP.")
@click.option("--cidr", "cidr", help="Authorize a CIDR range.")
@click.option("--repo", "repo", help="Authorize a repo (github.com/org).")
@click.option("--email", "email", help="Authorize an email.")
@click.option("--note", "note", default=None, help="Free-text note.")
def authz_add(domain, ip, cidr, repo, email, note):
    """Issue a new authorization token for a scope."""
    chosen = [("domain", domain), ("ip", ip), ("cidr", cidr), ("repo", repo), ("email", email)]
    provided = [(name, val) for name, val in chosen if val]
    if len(provided) != 1:
        raise click.UsageError("Provide exactly one of --domain/--ip/--cidr/--repo/--email.")
    name, val = provided[0]
    scope_map = {
        "domain": ScopeType.DOMAIN, "ip": ScopeType.IP, "cidr": ScopeType.CIDR,
        "repo": ScopeType.REPO, "email": ScopeType.EMAIL,
    }
    scope = AuthorizationScope(scope_map[name], val)
    reg = _registry()
    token = reg.issue(scope=scope, note=note)
    click.echo(f"token: {token}")
    click.echo(f"scope: {scope.type.value}={scope.value}")
    click.echo("status: unverified (run `secagent authz verify` after ownership proof)")


@authz.command("verify")
@click.argument("token")
@click.option("--method", default="dns_txt", type=click.Choice(["dns_txt", "file", "cert"]), help="Verification method used.")
def authz_verify(token, method):
    """Mark an authorization as verified (ownership has been proven)."""
    reg = _registry()
    record = reg.get(token)
    if record is None:
        raise click.UsageError(f"Unknown token: {token}")
    reg.mark_verified(token, method=method)
    click.echo(f"verified: {token} via {method}")


@authz.command("revoke")
@click.argument("token")
def authz_revoke(token):
    """Revoke an authorization token, preventing future use."""
    reg = _registry()
    record = reg.get(token)
    if record is None:
        raise click.UsageError(f"Unknown token: {token}")
    reg.revoke(token)
    click.echo(f"revoked: {token}")


@authz.command("list")
def authz_list():
    """List all authorization records."""
    reg = _registry()
    for r in reg.list():
        status = "verified" if r.verified else "unverified"
        revoked = " [REVOKED]" if getattr(r, 'revoked', False) else ""
        click.echo(f"{r.token}\t{r.scope.type.value}={r.scope.value}\t{status}{revoked}\t{r.created_at}\t{r.note or ''}")
