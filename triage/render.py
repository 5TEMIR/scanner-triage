from __future__ import annotations

from collections import Counter

from triage.models import SEVERITIES, Finding

_ICONS = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟦",
    "UNKNOWN": "⬜",
}


def _cell(value: str | None) -> str:
    return (value or "—").replace("|", "\\|").replace("\n", " ")


def render_markdown(
    findings: list[Finding],
    *,
    title: str = "Security triage report",
    min_severity: str | None = None,
) -> str:
    if min_severity:
        findings = [f for f in findings if f.is_at_least(min_severity)]

    counts = Counter(f.severity for f in findings)
    lines = [f"# {title}", ""]

    if not findings:
        lines += ["Findings not found.", ""]
        return "\n".join(lines)

    lines += [
        "## Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in SEVERITIES:
        if counts.get(severity):
            lines.append(f"| {_ICONS[severity]} {severity} | {counts[severity]} |")
    lines += [f"| **Total** | **{len(findings)}** |", ""]

    lines += ["## Findings", "", "| Severity | Source | Rule | Target | Details |", "| --- | --- | --- | --- | --- |"]
    for finding in findings:
        details = ""
        if finding.package:
            details = f"{finding.package} {finding.installed_version or ''}".strip()
            if finding.fixed_version:
                details += f" → {finding.fixed_version}"
        lines.append(
            "| {severity} | {source} | `{rule}` | `{target}` | {details} |".format(
                severity=finding.severity,
                source=finding.source,
                rule=_cell(finding.rule_id),
                target=_cell(finding.target),
                details=_cell(details),
            )
        )

    lines += ["", "## Details", ""]
    for finding in findings:
        location = finding.target
        if finding.line:
            location += f":{finding.line}"
        lines += [
            f"### [{finding.severity}] {finding.rule_id}",
            "",
            f"- **Source:** {finding.source}",
            f"- **Location:** `{location}`",
        ]
        if finding.package:
            lines.append(f"- **Package:** {finding.package} {finding.installed_version or ''}".rstrip())
        if finding.fixed_version:
            lines.append(f"- **Fixed in:** {finding.fixed_version}")
        lines.append(f"- **Fingerprint:** `{finding.fingerprint}`")
        if finding.description:
            lines += ["", finding.description]
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"
