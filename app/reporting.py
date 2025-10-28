"""Utilities for rendering custom reports."""
from __future__ import annotations

from typing import Iterable, List

from .models import Report, ReportSection, VulnerabilityCard, VulnerabilityIntelligence


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


def render_vulnerability_cards(cards: Iterable[VulnerabilityCard]) -> str:
    """Render vulnerability cards to Markdown for advanced reporting."""

    lines: List[str] = []
    for card in cards:
        lines.append(f"### {card.title} ({card.severity.value.title()} – score {card.risk_score:.2f})")
        lines.append("")
        lines.append(card.summary)
        if card.evidence:
            lines.append("")
            lines.append(f"**Evidence:** {card.evidence}")
        if card.recommendations:
            lines.append("")
            lines.append("**Recommendations**")
            for recommendation in card.recommendations:
                lines.append(f"- {recommendation}")
        lines.append("")
    return "\n".join(lines).strip()


def render_intelligence_overview(intelligence: VulnerabilityIntelligence) -> str:
    """Create a Markdown overview section from vulnerability intelligence."""

    lines = [
        f"**Composite Risk:** {intelligence.risk_level.value.title()} ({intelligence.risk_score:.2f})",
        "",
        intelligence.narrative,
        "",
        "**Insights**",
    ]
    for insight in intelligence.insights:
        lines.append(
            f"- {insight.vulnerability_class.value}: likelihood {insight.likelihood:.2f}, "
            f"impact {insight.impact:.2f}"
        )
    return "\n".join(lines).strip()
