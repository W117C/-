"""SecAgent CLI entry point."""
from __future__ import annotations

import click

from secagent.cli.audit import audit
from secagent.cli.authz import authz
from secagent.cli.findings import jobs, findings
from secagent.cli.report import report


@click.group()
def main() -> None:
    """SecAgent command-line interface."""


main.add_command(audit)
main.add_command(authz)
main.add_command(jobs)
main.add_command(findings)
main.add_command(report)
