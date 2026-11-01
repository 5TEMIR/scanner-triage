from pathlib import Path

import pytest

from triage.models import Finding, dedupe, normalize_severity, sort_findings
from triage.parsers import (
    UnsupportedReport,
    detect_format,
    load_reports,
    parse_report,
    parse_semgrep,
    parse_trivy,
)

FIXTURES = Path(__file__).parent / "fixtures"


def test_trivy_report_is_normalized() -> None:
    findings = parse_report(FIXTURES / "trivy.json")
    assert len(findings) == 3

    critical = next(f for f in findings if f.rule_id == "CVE-2024-33663")
    assert critical.severity == "CRITICAL"
    assert critical.package == "python-jose"
    assert critical.installed_version == "3.3.0"
    assert critical.fixed_version == "3.4.0"

    misconfig = next(f for f in findings if f.source == "trivy" and f.rule_id == "DS002")
    assert misconfig.target == "Dockerfile"
    assert misconfig.severity == "HIGH"


def test_semgrep_sarif_is_normalized() -> None:
    findings = parse_report(FIXTURES / "semgrep.sarif")
    assert len(findings) == 2
    first = findings[0]
    assert first.source == "semgrep"
    assert first.target == "app/main.py"
    assert first.line == 42
    assert first.severity == "HIGH"  # SARIF "error"


def test_clean_trivy_report_has_no_findings() -> None:
    # Trivy omits "Results" when nothing was found - that is still a valid report.
    assert parse_report(FIXTURES / "trivy-clean.json") == []


def test_semgrep_uses_rule_default_level() -> None:
    # Semgrep leaves "level" off the result and relies on the rule default.
    payload = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {"id": "err-rule", "defaultConfiguration": {"level": "error"}},
                            {"id": "note-rule", "defaultConfiguration": {"level": "note"}},
                        ]
                    }
                },
                "results": [
                    {"ruleId": "err-rule", "message": {"text": "boom"}},
                    {"ruleId": "note-rule", "message": {"text": "fyi"}},
                ],
            }
        ]
    }
    findings = parse_semgrep(payload)
    assert [f.severity for f in findings] == ["HIGH", "LOW"]


def test_trivy_secret_is_normalized() -> None:
    findings = parse_report(FIXTURES / "trivy-secret.json")
    assert len(findings) == 1
    secret = findings[0]
    assert secret.source == "trivy"
    assert secret.rule_id == "github-pat"
    assert secret.severity == "CRITICAL"
    assert secret.target == "app/config.py"
    assert secret.line == 7
    # the matched value (masked or not) must never reach the report
    assert secret.description == ""


def test_trivy_secret_match_is_not_echoed() -> None:
    payload = {
        "Results": [
            {
                "Target": "app.py",
                "Secrets": [
                    {"RuleID": "generic-api-key", "Severity": "HIGH", "Match": "api_key=DO-NOT-COPY"}
                ],
            }
        ]
    }
    findings = parse_trivy(payload)
    assert len(findings) == 1
    assert "DO-NOT-COPY" not in findings[0].description
    assert "DO-NOT-COPY" not in findings[0].title


def test_unknown_report_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "report.json"
    report.write_text('{"foo": "bar"}', encoding="utf-8")
    with pytest.raises(UnsupportedReport):
        parse_report(report)


def test_invalid_json_is_rejected(tmp_path: Path) -> None:
    report = tmp_path / "broken.json"
    report.write_text("{not json", encoding="utf-8")
    with pytest.raises(UnsupportedReport):
        parse_report(report)


def test_severity_aliases() -> None:
    assert normalize_severity("error") == "HIGH"
    assert normalize_severity("Moderate") == "MEDIUM"
    assert normalize_severity(None) == "UNKNOWN"
    assert normalize_severity("weird") == "UNKNOWN"


def test_dedupe_keeps_single_finding() -> None:
    finding = Finding("trivy", "CVE-1", "title", "HIGH", "image")
    assert dedupe([finding, finding]) == [finding]


def test_dedupe_keeps_different_locations() -> None:
    a = Finding("semgrep", "rule", "title", "HIGH", "a.py", line=1)
    b = Finding("semgrep", "rule", "title", "HIGH", "a.py", line=2)
    assert len(dedupe([a, b])) == 2


def test_sort_puts_critical_first() -> None:
    low = Finding("trivy", "L", "t", "LOW", "x")
    critical = Finding("trivy", "C", "t", "CRITICAL", "x")
    assert sort_findings([low, critical])[0] is critical


def test_multiple_reports_are_merged() -> None:
    findings = load_reports([FIXTURES / "trivy.json", FIXTURES / "semgrep.sarif"])
    assert len(findings) == 5
    assert {f.source for f in findings} == {"trivy", "semgrep"}


def test_detect_format() -> None:
    assert detect_format({"runs": []}) == "semgrep"
    assert detect_format({"Results": []}) == "trivy"


def test_detect_clean_trivy_report() -> None:
    assert detect_format({"SchemaVersion": 2, "ArtifactType": "filesystem"}) == "trivy"
