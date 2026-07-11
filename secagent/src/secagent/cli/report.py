"""`secagent report` — generate human-readable reports from historical findings (P2)."""
from __future__ import annotations

import json
import sys

import click

from secagent.config import Config
from secagent.report import render_json, render_markdown
from secagent.report.pdf_report import render_pdf
from secagent.storage.sqlite_store import SQLiteStore


def _query_findings(tool: str | None = None, target: str | None = None,
                    severity: str | None = None, limit: int = 0) -> list[dict]:
    """Query the findings table and return engagement-compatible dicts."""
    store = _store()
    conn = store._connect()
    try:
        where = []
        params: list = []
        if tool:
            where.append("f.tool = ?")
            params.append(tool)
        if severity:
            where.append("f.severity = ?")
            params.append(severity)
        if target:
            where.append("f.target LIKE ?")
            params.append(f"%{target}%")

        sql = """SELECT f.id, f.engagement_id, f.tool, f.type, f.severity,
                        f.target, f.title, f.evidence_json, f.source_tool, f.created_at
                 FROM findings f"""
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY f.created_at DESC"
        if limit > 0:
            sql += " LIMIT ?"
            params.append(limit)

        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()

    # Group by engagement_id
    engagements: dict[str, dict] = {}
    for r in rows:
        eng_id = r[1] or "no_engagement"
        if eng_id not in engagements:
            engagements[eng_id] = {
                "engagement_id": eng_id,
                "tool": r[2],
                "findings": [],
                "quota_used": 1,
            }
        engagements[eng_id]["findings"].append({
            "id": r[0],
            "type": r[3],
            "severity": r[4],
            "target": r[5],
            "title": r[6],
            "evidence": json.loads(r[7]) if r[7] else {},
            "source_tool": r[8],
            "timestamp": r[9],
        })

    return list(engagements.values())


def _store() -> SQLiteStore:
    cfg = Config.load()
    store = SQLiteStore(cfg.db_path)
    store.bootstrap()
    return store


@click.group()
def report() -> None:
    """Generate scan reports."""


@report.command("generate")
@click.option("--tool", default=None, help="Filter by tool name.")
@click.option("--target", default=None, help="Filter by target (substring match).")
@click.option("--severity", default=None, help="Filter by severity.")
@click.option("--format", "fmt", default="markdown", type=click.Choice(["markdown", "json", "pdf"]),
              help="Output format.")
@click.option("--output", default=None, help="Output file path (default: stdout). For pdf, a .pdf path is required.")
@click.option("--limit", default=200, type=int, help="Max findings to include.")
def report_generate(tool, target, severity, fmt, output, limit):
    """Generate a report from historical findings."""
    engagements = _query_findings(tool=tool, target=target, severity=severity, limit=limit)

    if not engagements:
        click.echo("No findings match the criteria.", err=True)
        sys.exit(0)

    if fmt == "markdown":
        body = render_markdown(engagements)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(body)
            click.echo(f"Report written to {output}")
        else:
            click.echo(body)
    elif fmt == "json":
        body = render_json(engagements)
        if output:
            with open(output, "w", encoding="utf-8") as f:
                f.write(body)
            click.echo(f"Report written to {output}")
        else:
            click.echo(body)
    else:  # pdf
        if not output:
            click.echo("Error: --output PATH.pdf is required for pdf format.", err=True)
            sys.exit(2)
        render_pdf(engagements, output)
        click.echo(f"PDF report written to {output}")
