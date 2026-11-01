from pathlib import Path

from triage.models import Finding
from triage.render import render_markdown

FIXTURES = Path(__file__).parent / "fixtures"


def test_report_contains_summary_and_details() -> None:
    findings = [
        Finding("trivy", "CVE-2024-33663", "jose confusion", "CRITICAL", "Python", package="python-jose"),
        Finding("semgrep", "eval-detected", "use of eval", "HIGH", "app/main.py", line=42),
    ]
    report = render_markdown(findings)
    assert "# Security triage report" in report
    assert "**Total** | **2**" in report
    assert "CVE-2024-33663" in report
    assert "app/main.py:42" in report


def test_min_severity_filters_low_findings() -> None:
    findings = [
        Finding("semgrep", "low-rule", "low", "LOW", "a.py"),
        Finding("semgrep", "high-rule", "high", "HIGH", "b.py"),
    ]
    report = render_markdown(findings, min_severity="HIGH")
    assert "high-rule" in report
    assert "low-rule" not in report


def test_empty_report_is_explicit() -> None:
    assert "Findings not found" in render_markdown([])


def test_pipe_characters_are_escaped() -> None:
    report = render_markdown([Finding("trivy", "rule|id", "title", "HIGH", "img")])
    assert "rule\\|id" in report
    assert "| HIGH | trivy | `rule\\|id` |" in report
