"""Utilities for rendering custom reports."""
from __future__ import annotations

from typing import Iterable

from .models import Report, ReportSection


def build_markdown(report: Report) -> str:
    """Render a report to Markdown for exporting or editing."""

    lines = [f"# {report.title}", ""]
    for section in report.sections:
        if not section.include:
            continue
        lines.append(f"## {section.title}")
        if section.content:
            lines.append(section.content)
        else:
            lines.append("_This section is intentionally left blank pending analysis._")
        lines.append("")
    return "\n".join(lines).strip()


def summarize_vulnerabilities(sections: Iterable[ReportSection]) -> str:
    """Produce a compact summary of included vulnerabilities."""

    included = [section.title for section in sections if section.include]
    return ", ".join(included)
