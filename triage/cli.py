from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

from triage.gitlab import GitLabClient, GitLabError
from triage.models import SEVERITIES, dedupe, normalize_severity, sort_findings
from triage.parsers import UnsupportedReport, load_reports
from triage.render import render_markdown

LOGGER = logging.getLogger("triage")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="triage",
        description="Normalize Trivy/Semgrep reports, render a Markdown report and file GitLab issues.",
    )
    parser.add_argument("reports", nargs="+", help="Trivy JSON and/or Semgrep SARIF files")
    parser.add_argument("-o", "--output", default="security-report.md", help="Markdown report path")
    parser.add_argument("--title", default="Security triage report")
    parser.add_argument(
        "--min-severity",
        choices=SEVERITIES,
        default=None,
        help="Only include findings at or above this severity",
    )
    parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        help="Exit with code 1 when a finding at or above this severity is present (CI gate)",
    )
    parser.add_argument(
        "--create-issues",
        action="store_true",
        help="Create GitLab issues for findings (requires GITLAB_TOKEN and --project-id)",
    )
    parser.add_argument("--gitlab-url", default=os.getenv("CI_API_V4_URL", "https://gitlab.com"))
    parser.add_argument("--project-id", default=os.getenv("CI_PROJECT_ID"))
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(message)s",
    )

    try:
        findings = sort_findings(dedupe(load_reports(args.reports)))
    except (OSError, UnsupportedReport) as exc:
        LOGGER.error("%s", exc)
        return 2

    report = render_markdown(findings, title=args.title, min_severity=args.min_severity)
    Path(args.output).write_text(report, encoding="utf-8")
    LOGGER.info("report written to %s (%d finding(s))", args.output, len(findings))

    if args.create_issues:
        if not args.project_id:
            LOGGER.error("--project-id or CI_PROJECT_ID is required to create issues")
            return 2
        token = os.getenv("GITLAB_TOKEN", "")
        if not token:
            LOGGER.error("GITLAB_TOKEN environment variable is not set")
            return 2
        client = GitLabClient(
            args.gitlab_url,
            token,
            args.project_id,
            timeout=args.timeout,
            retries=args.retries,
        )
        for finding in findings:
            if args.min_severity and not finding.is_at_least(args.min_severity):
                continue
            try:
                issue = client.create_issue(finding)
            except GitLabError as exc:
                LOGGER.error("cannot create issue for %s: %s", finding.fingerprint, exc)
                return 1
            LOGGER.info("issue #%s created for %s", issue.get("iid", "?"), finding.rule_id)

    if args.fail_on:
        threshold = normalize_severity(args.fail_on)
        blocking = [f for f in findings if f.is_at_least(threshold)]
        if blocking:
            LOGGER.error("%d finding(s) at or above %s", len(blocking), threshold)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
