"""`secagent jobs` and `secagent findings` — async job management + result review (P0/P1)."""
from __future__ import annotations

import json

import click

from secagent.config import Config
from secagent.core.scheduler import JobManager
from secagent.storage.sqlite_store import SQLiteStore


def _store() -> SQLiteStore:
    cfg = Config.load()
    store = SQLiteStore(cfg.db_path)
    store.bootstrap()
    return store


def _manager() -> JobManager:
    cfg = Config.load()
    return JobManager(config=cfg)


# ---------------------------------------------------------------------------
# secagent jobs
# ---------------------------------------------------------------------------

@click.group()
def jobs() -> None:
    """Manage async scan jobs."""


@jobs.command("list")
@click.option("--tool", default=None, help="Filter by tool name.")
@click.option("--limit", default=20, type=int, help="Max entries.")
def jobs_list(tool, limit):
    """List recent async scan jobs."""
    mgr = _manager()
    results = mgr.list_jobs(tool=tool, limit=limit)
    if not results:
        click.echo("No jobs found.")
        return
    click.echo(f"{'JOB ID':<28} {'TOOL':<22} {'STATUS':<10} {'CREATED AT'}")
    click.echo("-" * 80)
    for j in results:
        click.echo(f"{j['job_id']:<28} {j['tool']:<22} {j['status']:<10} {j['created_at']}")


@jobs.command("show")
@click.argument("job_id")
def jobs_show(job_id):
    """Show details of a specific job."""
    mgr = _manager()
    result = mgr.poll_result(job_id=job_id)

    if "error" in result:
        click.echo(f"Error: {result['error']['message']}")
        return

    click.echo(f"Job ID:     {result.get('job_id', '')}")
    click.echo(f"Tool:       {result.get('tool', '')}")
    click.echo(f"Status:     {result.get('status', '')}")

    if result.get("status") == "done":
        findings = result.get("findings", [])
        click.echo(f"Findings:   {len(findings)}")
        click.echo(f"Engagement: {result.get('engagement_id', '')}")
        click.echo(f"Quota used: {result.get('quota_used', 0)}")
        if findings:
            click.echo("\nFindings:")
            for f in findings:
                click.echo(
                    f"  [{f.get('severity', '?').upper():>8}] "
                    f"{f.get('target', '')} — {f.get('title', '')}"
                )
    elif result.get("status") == "failed":
        click.echo(f"Error:      {result.get('error_message', 'unknown')}")
    else:
        click.echo(f"Started at: {result.get('started_at', '')}")
        output = result.get("output_buffer", "")
        if output:
            click.echo(f"\nPartial output:\n{output[:500]}")


# ---------------------------------------------------------------------------
# secagent findings
# ---------------------------------------------------------------------------

@click.group()
def findings() -> None:
    """Query historical findings."""


@findings.command("list")
@click.option("--tool", default=None, help="Filter by tool name.")
@click.option("--target", default=None, help="Filter by target (substring match).")
@click.option("--severity", default=None, help="Filter by severity (info/low/medium/high/critical).")
@click.option("--limit", default=50, type=int, help="Max entries.")
@click.option("--json-output", "json_output", is_flag=True, default=False, help="Output as JSON.")
def findings_list(tool, target, severity, limit, json_output):
    """List historical findings."""
    store = _store()
    conn = store._connect()
    try:
        where = []
        params: list = []
        if tool:
            where.append("tool = ?")
            params.append(tool)
        if severity:
            where.append("severity = ?")
            params.append(severity)
        if target:
            where.append("target LIKE ?")
            params.append(f"%{target}%")

        where_clause = " AND ".join(where) if where else ""
        sql = "SELECT id, tool, type, severity, target, title, created_at FROM findings"
        if where_clause:
            sql += " WHERE " + where_clause
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    if not rows:
        click.echo("No findings found.")
        return

    if json_output:
        out = [
            {"id": r[0], "tool": r[1], "type": r[2], "severity": r[3],
             "target": r[4], "title": r[5], "created_at": r[6]}
            for r in rows
        ]
        click.echo(json.dumps(out, ensure_ascii=False, indent=2))
        return

    click.echo(f"{'ID':<20} {'TOOL':<20} {'TYPE':<16} {'SEV':<8} {'TARGET':<40} {'TITLE'}")
    click.echo("-" * 140)
    for r in rows:
        click.echo(f"{r[0]:<20} {r[1]:<20} {r[2]:<16} {r[3]:<8} {r[4]:<40} {r[5]}")


# ---------------------------------------------------------------------------
# secagent findings diff
# ---------------------------------------------------------------------------

def _fingerprint(f: dict) -> str:
    """Create a stable fingerprint for a finding to detect changes."""
    return f"{f['tool']}|{f['type']}|{f['target']}|{f['title']}"


def _fetch_engagement(store: SQLiteStore, engagement_id: str) -> list[dict]:
    """Fetch all findings for an engagement."""
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT id, tool, type, severity, target, title, created_at "
            "FROM findings WHERE engagement_id=? ORDER BY created_at",
            (engagement_id,),
        ).fetchall()
        return [
            {"id": r[0], "tool": r[1], "type": r[2], "severity": r[3],
             "target": r[4], "title": r[5], "created_at": r[6]}
            for r in rows
        ]
    finally:
        conn.close()


def _fetch_recent(store: SQLiteStore, hours: int) -> list[dict]:
    """Fetch findings from the last N hours."""
    import datetime as dt
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT id, tool, type, severity, target, title, created_at "
            "FROM findings WHERE created_at >= ? ORDER BY created_at",
            (cutoff.isoformat(),),
        ).fetchall()
        return [
            {"id": r[0], "tool": r[1], "type": r[2], "severity": r[3],
             "target": r[4], "title": r[5], "created_at": r[6]}
            for r in rows
        ]
    finally:
        conn.close()


def _find_engagement_ids(store: SQLiteStore) -> list[tuple[str, str, int]]:
    """Return list of (engagement_id, tool, finding_count) for recent engagements."""
    conn = store._connect()
    try:
        rows = conn.execute(
            "SELECT engagement_id, tool, COUNT(*) as cnt, MAX(created_at) as latest "
            "FROM findings WHERE engagement_id != '' AND engagement_id IS NOT NULL "
            "GROUP BY engagement_id ORDER BY latest DESC LIMIT 20"
        ).fetchall()
        return [(r[0], r[1], r[2]) for r in rows]
    finally:
        conn.close()


def _print_diff(old_set: set, new_set: set, old_name: str, new_name: str, findings_map: dict) -> None:
    """Print a diff between two sets of finding fingerprints."""
    new_in_new = new_set - old_set
    gone = old_set - new_set
    common = old_set & new_set

    click.echo(f"\n{'='*70}")
    click.echo(f"Diff: {old_name} → {new_name}")
    click.echo(f"{'='*70}")

    if new_in_new:
        click.echo(f"\n🆕 **NEW** ({len(new_in_new)}):")
        for fp in sorted(new_in_new):
            f = findings_map.get(fp, {})
            click.echo(f"  [{f.get('severity', '?'):>8}] {f.get('target', '')} — {f.get('title', '')}")

    if gone:
        click.echo(f"\n✅ **RESOLVED** ({len(gone)}):")
        for fp in sorted(gone):
            f = findings_map.get(fp, {})
            click.echo(f"  [{f.get('severity', '?'):>8}] {f.get('target', '')} — {f.get('title', '')}")

    if not new_in_new and not gone:
        click.echo("\nNo changes detected — both sets are identical.")
    else:
        click.echo(f"\nSummary: +{len(new_in_new)} new, -{len(gone)} resolved, {len(common)} unchanged")


@findings.command("diff")
@click.option("--old-engagement", default=None, help="Old engagement ID to compare from.")
@click.option("--new-engagement", default=None, help="New engagement ID to compare to.")
@click.option("--old-hours", type=int, default=None, help="Old time window in hours.")
@click.option("--new-hours", type=int, default=None, help="New time window in hours.")
@click.option("--list-engagements", is_flag=True, default=False, help="List available engagement IDs.")
def findings_diff(old_engagement, new_engagement, old_hours, new_hours, list_engagements):
    """Compare scan results across engagements or time windows.

    Shows what findings are NEW, RESOLVED, or UNCHANGED between two
    scan runs or time periods. Useful for tracking progress after
    applying security fixes.

    Examples:
      secagent findings diff --old-engagement eng_abc --new-engagement eng_def
      secagent findings diff --old-hours 48 --new-hours 24
      secagent findings diff --list-engagements
    """
    store = _store()

    if list_engagements:
        engagements = _find_engagement_ids(store)
        if not engagements:
            click.echo("No engagements found.")
            return
        click.echo(f"{'ENGAGEMENT ID':<24} {'TOOL':<22} {'FINDINGS'}")
        click.echo("-" * 60)
        for eid, tool, cnt in engagements:
            click.echo(f"{eid:<24} {tool:<22} {cnt}")
        return

    # Fetch old and new finding sets
    old_name = ""
    new_name = ""

    if old_engagement and new_engagement:
        old_findings = _fetch_engagement(store, old_engagement)
        new_findings = _fetch_engagement(store, new_engagement)
        old_name = f"engagement {old_engagement}"
        new_name = f"engagement {new_engagement}"
    elif old_hours is not None and new_hours is not None:
        old_findings = _fetch_recent(store, old_hours)
        new_findings = _fetch_recent(store, new_hours)
        old_name = f"last {old_hours}h"
        new_name = f"last {new_hours}h"
    elif old_hours is not None:
        # Single time window: compare against everything before
        old_findings = _fetch_recent(store, 8760)  # 1 year
        new_findings = _fetch_recent(store, old_hours)
        old_name = "all time"
        new_name = f"last {old_hours}h"
    else:
        click.echo("Specify --old-engagement/--new-engagement or --old-hours/--new-hours")
        click.echo("Use --list-engagements to see available engagement IDs.")
        return

    # Build fingerprint sets
    all_findings: dict[str, dict] = {}
    old_set: set[str] = set()
    for f in old_findings:
        fp = _fingerprint(f)
        old_set.add(fp)
        all_findings[fp] = f

    new_set: set[str] = set()
    for f in new_findings:
        fp = _fingerprint(f)
        new_set.add(fp)
        all_findings[fp] = f

    _print_diff(old_set, new_set, old_name, new_name, all_findings)
