"""SecAgent CLI entry point."""
from __future__ import annotations

import click

from secagent.cli.audit import audit
from secagent.cli.authz import authz
from secagent.cli.findings import findings, jobs
from secagent.cli.hunterone import hunterone
from secagent.cli.monitor import monitor
from secagent.cli.report import report

__all__ = [
    "main",
    "audit",
    "authz",
    "findings",
    "hunterone",
    "monitor",
    "report",
    "jobs",
]


@click.group()
def main() -> None:
    """SecAgent command-line interface."""


main.add_command(audit)
main.add_command(authz)
main.add_command(findings)
main.add_command(hunterone)
main.add_command(jobs)
main.add_command(monitor)
main.add_command(report)
