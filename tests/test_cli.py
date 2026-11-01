from pathlib import Path

from triage.cli import main

FIXTURES = Path(__file__).parent / "fixtures"


def test_cli_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    code = main([str(FIXTURES / "trivy.json"), "-o", str(output)])
    assert code == 0
    assert "CVE-2024-33663" in output.read_text(encoding="utf-8")


def test_cli_fails_on_threshold(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    code = main([str(FIXTURES / "trivy.json"), "-o", str(output), "--fail-on", "CRITICAL"])
    assert code == 1


def test_cli_passes_below_threshold(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    code = main([str(FIXTURES / "semgrep.sarif"), "-o", str(output), "--fail-on", "CRITICAL"])
    assert code == 0


def test_cli_rejects_unknown_report(tmp_path: Path) -> None:
    report = tmp_path / "unknown.json"
    report.write_text("{}", encoding="utf-8")
    assert main([str(report), "-o", str(tmp_path / "out.md")]) == 2


def test_cli_accepts_clean_report(tmp_path: Path) -> None:
    output = tmp_path / "report.md"
    code = main([str(FIXTURES / "trivy-clean.json"), "-o", str(output), "--fail-on", "LOW"])
    assert code == 0
    assert "Findings not found" in output.read_text(encoding="utf-8")
