"""`secagent monitor` — continuous re-scan scheduling (spec §M7).

Commands:
  secagent monitor add   --name N --target T --token TOK --interval-hours H [--modules ...]
  secagent monitor list
  secagent monitor run   --name N          # run one task immediately
  secagent monitor tick                   # run all due tasks (cron-friendly)
  secagent monitor remove --name N
"""
from __future__ import annotations

import click

from secagent.config import Config
from secagent.core.monitor import MonitorStore


def _store() -> MonitorStore:
    return MonitorStore(config=Config.load())


@click.group()
def monitor() -> None:
    """Continuous monitoring: scheduled re-scans with change detection."""


@monitor.command("add")
@click.option("--name", required=True, help="Unique task name.")
@click.option("--target", required=True, help="Target URL to monitor.")
@click.option("--token", "token", required=True, help="Authorization token (from `secagent authz add`).")
@click.option("--interval-hours", type=int, required=True, help="Re-scan interval in hours.")
@click.option("--modules", default="sqli,xss,ssrf,lfi", help="Comma-separated modules.")
def monitor_add(name, target, token, interval_hours, modules):
    """Register a new monitor task."""
    mods = [m.strip() for m in modules.split(",") if m.strip()]
    task_id = _store().add_task(
        name=name, target=target, token=token,
        interval_hours=interval_hours, modules=mods,
    )
    click.echo(f"Added monitor task '{name}' (id={task_id}, every {interval_hours}h).")


@monitor.command("list")
def monitor_list():
    """List all monitor tasks."""
    tasks = _store().list_tasks()
    if not tasks:
        click.echo("No monitor tasks.")
        return
    click.echo(f"{'NAME':<20} {'TARGET':<40} {'EVERY':<8} {'ENABLED':<8} {'LAST RUN'}")
    click.echo("-" * 100)
    for t in tasks:
        click.echo(
            f"{t['name']:<20} {t['target']:<40} {str(t['interval_hours'])+'h':<8} "
            f"{'yes' if t['enabled'] else 'no':<8} {t['last_run_at'] or 'never'}"
        )


@monitor.command("run")
@click.option("--name", required=True, help="Task name to run now.")
def monitor_run(name):
    """Run a single monitor task immediately."""
    store = _store()
    task = store.get_task(name)
    if task is None:
        click.echo(f"Error: no such task '{name}'.")
        return
    import datetime as dt
    summary = store._run_task(task, dt.datetime.now(dt.timezone.utc))
    _echo_summary(summary)


@monitor.command("tick")
def monitor_tick():
    """Run all due tasks. Intended to be called by cron on a fixed schedule."""
    summaries = _store().tick()
    if not summaries:
        click.echo("No tasks due.")
        return
    for s in summaries:
        _echo_summary(s)


@monitor.command("remove")
@click.option("--name", required=True, help="Task name to remove.")
def monitor_remove(name):
    """Remove a monitor task."""
    if _store().delete_task(name):
        click.echo(f"Removed task '{name}'.")
    else:
        click.echo(f"Error: no such task '{name}'.")


def _echo_summary(s: dict) -> None:
    if s.get("status") == "error":
        click.echo(f"[!] {s['task']} ({s['target']}): ERROR {s.get('error')}")
        return
    click.echo(
        f"[✓] {s['task']} ({s['target']}): "
        f"{s['total_findings']} findings, {s['new_findings']} NEW"
    )
    for f in s.get("new", []):
        click.echo(
            f"    [{f.get('severity','?'):>8}] {f.get('title','')}"
        )
