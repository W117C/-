"""`secagent hunterone` — HackerOne bug-bounty workflow (recon → scan → report → learn).

Provides a single `workflow` command that orchestrates the full 5-step pipeline:

  1. Architecture identification (SPA / MPA / RSC)
  2. Endpoint discovery from JS assets
  3. Vulnerability scanning (with --token for active exploits)
  4. HackerOne-format report generation (adversary thinking framework)
  5. Knowledge-archival retrospective prompt

Methodology: [[real-target-web-vuln-methodology]]
Toolchain:   [[secagent]]

Examples
--------
    # Reconnaissance only (no active scanning):
    secagent hunterone workflow https://example.com

    # With active vulnerability scan:
    secagent hunterone workflow https://example.com --token YOUR_TOKEN

    # Custom output directory:
    secagent hunterone workflow https://example.com --output ./my-reports
"""

from __future__ import annotations

import logging
import sys

import click

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")


@click.group()
def hunterone() -> None:
    """Manage HackerOne bug-bounty workflow."""


@hunterone.command("workflow")
@click.argument("target")
@click.option("--token", default=None, help="SecAgent authz token for active vulnerability scans.")
@click.option("--output", "-o", default="./reports", help="Directory for generated reports.")
@click.option("--bbp", default=None, type=click.Choice(["tiktok"]),
              help="BBP profile: applies program-specific policies (rate limits, exclusions, report format).")
@click.option("--h1-username", default=None, help="Your HackerOne username (required for some BBP programs like TikTok).")
@click.option("--cookie", default="", help="Cookie string for authenticated scanning (e.g. 'session=abc123; token=xyz').")
@click.option("--post-params", default="", help="Comma-separated param names for POST JSON body fuzzing (e.g. 'id,email,token').")
def hunterone_workflow(target: str, token: str | None, output: str,
                       bbp: str | None, h1_username: str | None,
                       cookie: str, post_params: str) -> None:
    """Run the full HackerOne bounty workflow against a target URL.

    Steps:
      1. Architecture identification (SPA/MPA/RSC detection)
      2. Endpoint discovery (JS-extracted API routes)
      3. Vulnerability scanning (if --token provided)
      4. HackerOne-format report with adversary thinking
      5. Retrospective prompt for knowledge archival

    Without --token, only Steps 1-2 and 4-5 run (safe reconnaissance).
    """
    from secagent.workflow.hunterone import HackerOneWorkflow

    click.echo(f"\n{'='*70}")
    click.echo(f"HackerOne Workflow — {target}")
    click.echo(f"{'='*70}\n")

    wf = HackerOneWorkflow(
        target=target,
        authz_token=token,
        output_dir=output,
        bbp_profile=bbp,
        h1_username=h1_username,
        cookie=cookie,
        post_body_params=[p.strip() for p in post_params.split(",") if p.strip()] if post_params else [],
    )

    try:
        report_path = wf.run()

        click.echo(f"\n{'='*70}")
        click.echo("✅ Workflow complete")
        click.echo(f"{'='*70}")
        click.echo(f"📄 Report: {report_path}")

        if not token:
            click.echo("")
            click.echo("💡 Tip: Add --token YOUR_TOKEN to include active vulnerability scanning.")
            click.echo("   Register a token first:  secagent authz add \\")
            click.echo("       --scope-type wildcard --scope-value '*' --token YOUR_TOKEN")

        # Print any warnings
        click.echo("")
        click.echo("📋 Steps executed:")
        click.echo("   1. ✅ Architecture identification")
        click.echo("   2. ✅ Endpoint discovery")
        click.echo(f"   3. {'✅ Vulnerability scan' if token else '⏭️  Skipped (no token)'}")
        click.echo("   4. ✅ HackerOne report generated")
        click.echo("   5. 📝 See retrospective section in report for knowledge archival")

    except Exception as e:
        click.echo(f"\n❌ Workflow failed: {e}", err=True)
        logging.getLogger(__name__).exception("Workflow error")
        sys.exit(1)
