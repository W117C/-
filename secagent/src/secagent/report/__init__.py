"""Report generators: render engagement dicts as JSON / Markdown / PDF / client report."""
from secagent.report.client_report import render_client_report
from secagent.report.json_report import render_json
from secagent.report.markdown_report import render_markdown

try:
    from secagent.report.pdf_report import render_pdf
    __all__ = ["render_json", "render_markdown", "render_client_report", "render_pdf"]
except ImportError:  # pragma: no cover — reportlab optional at import time
    __all__ = ["render_json", "render_markdown", "render_client_report"]
