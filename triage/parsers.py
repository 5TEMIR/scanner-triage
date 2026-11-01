from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from triage.models import Finding


class UnsupportedReport(ValueError):
    """Raised when the input is neither a Trivy nor a Semgrep report."""


def _clip(text: str | None, limit: int = 600) -> str:
    if not text:
        return ""
    return " ".join(str(text).split())[:limit]


def parse_trivy(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        target = result.get("Target") or "unknown"
        for vuln in result.get("Vulnerabilities") or []:
            findings.append(
                Finding(
                    source="trivy",
                    rule_id=vuln.get("VulnerabilityID") or "UNKNOWN-CVE",
                    title=_clip(vuln.get("Title") or vuln.get("VulnerabilityID"), 160),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    target=target,
                    package=vuln.get("PkgName"),
                    installed_version=vuln.get("InstalledVersion"),
                    fixed_version=vuln.get("FixedVersion") or None,
                    description=_clip(vuln.get("Description")),
                )
            )
        for misconfig in result.get("Misconfigurations") or []:
            findings.append(
                Finding(
                    source="trivy",
                    rule_id=misconfig.get("ID") or misconfig.get("AVDID") or "UNKNOWN-MISCONFIG",
                    title=_clip(misconfig.get("Title"), 160),
                    severity=misconfig.get("Severity", "UNKNOWN"),
                    target=target,
                    description=_clip(misconfig.get("Description")),
                )
            )
    return findings


def parse_semgrep(payload: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    for run in payload.get("runs") or []:
        for result in run.get("results") or []:
            locations = result.get("locations") or [{}]
            physical = locations[0].get("physicalLocation") or {}
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            message = _clip((result.get("message") or {}).get("text"))
            findings.append(
                Finding(
                    source="semgrep",
                    rule_id=result.get("ruleId") or "UNKNOWN-RULE",
                    title=_clip(message, 160) or result.get("ruleId", ""),
                    severity=result.get("level", "WARNING"),
                    target=artifact.get("uri") or "unknown",
                    line=region.get("startLine"),
                    description=message,
                )
            )
    return findings


def detect_format(payload: Any) -> str:
    if isinstance(payload, dict):
        if "runs" in payload:
            return "semgrep"
        if "Results" in payload:
            return "trivy"
    raise UnsupportedReport("expected a Trivy JSON or a Semgrep SARIF report")


def parse_report(path: str | Path) -> list[Finding]:
    path = Path(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise UnsupportedReport(f"{path}: invalid JSON ({exc.msg})") from exc
    fmt = detect_format(payload)
    if fmt == "semgrep":
        return parse_semgrep(payload)
    return parse_trivy(payload)


def load_reports(paths: list[str | Path]) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        findings.extend(parse_report(path))
    return findings
