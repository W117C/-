"""SecAgent CLI entry point."""
from __future__ import annotations

import click

from secagent.cli.authz import authz


@click.group()
def main() -> None:
    """SecAgent command-line interface."""


main.add_command(authz)
