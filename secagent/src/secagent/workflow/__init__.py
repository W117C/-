"""SecAgent workflow engine — automated bounty-hunting pipelines.

HackerOne workflow:
    from secagent.workflow.hunterone import HackerOneWorkflow
    wf = HackerOneWorkflow(target="https://example.com")
    report = wf.run()
"""

from __future__ import annotations

__all__ = ["HackerOneWorkflow"]

from secagent.workflow.hunterone import HackerOneWorkflow  # noqa: E402, F401
