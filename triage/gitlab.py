from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from triage.models import Finding

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class GitLabError(RuntimeError):
    """Raised when the GitLab API call cannot be completed."""


class GitLabClient:
    """Minimal GitLab Issues client with timeouts, retries and safe logging."""

    def __init__(
        self,
        base_url: str,
        token: str,
        project_id: str | int,
        *,
        timeout: float = 10.0,
        retries: int = 3,
        backoff: float = 1.0,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not token:
            raise ValueError("GitLab token is required")
        if retries < 0:
            raise ValueError("retries must be non-negative")
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise ValueError("base_url must be an absolute http(s) URL")
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._project_id = urllib.parse.quote(str(project_id), safe="")
        self._timeout = timeout
        self._retries = retries
        self._backoff = backoff
        self._sleep = sleep

    @property
    def _issues_url(self) -> str:
        return f"{self._base_url}/api/v4/projects/{self._project_id}/issues"

    def create_issue(self, finding: Finding) -> dict[str, Any]:
        payload = {
            "title": f"[{finding.severity}] {finding.rule_id}: {finding.title}"[:255],
            "description": self._issue_body(finding),
            "labels": f"security,{finding.severity.lower()}",
        }
        return self._request("POST", self._issues_url, payload)

    @staticmethod
    def _issue_body(finding: Finding) -> str:
        lines = [
            f"**Source:** `{finding.source}`",
            f"**Location:** `{finding.target}`" + (f":{finding.line}" if finding.line else ""),
        ]
        if finding.package:
            lines.append(f"**Package:** `{finding.package} {finding.installed_version or ''}`".rstrip())
        if finding.fixed_version:
            lines.append(f"**Fixed in:** `{finding.fixed_version}`")
        lines += [
            "",
            finding.description or "_No description provided by the scanner._",
            "",
            "---",
            f"Fingerprint: `{finding.fingerprint}`",
            "_Created automatically by scanner-triage._",
        ]
        return "\n".join(lines)

    def _request(self, method: str, url: str, payload: dict[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            url,
            data=body,
            method=method,
            headers={
                "PRIVATE-TOKEN": self._token,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        last_error: str = "unknown error"
        for attempt in range(self._retries + 1):
            try:
                # base_url is restricted to absolute http(s) URLs in __init__.
                # nosemgrep
                with urllib.request.urlopen(request, timeout=self._timeout) as response:
                    raw = response.read()
                    return json.loads(raw) if raw else {}
            except urllib.error.HTTPError as exc:
                last_error = f"HTTP {exc.code}"
                if exc.code not in RETRYABLE_STATUS or attempt == self._retries:
                    break
            except (urllib.error.URLError, TimeoutError) as exc:
                last_error = f"connection error: {exc}"
                if attempt == self._retries:
                    break
            if attempt < self._retries:
                self._sleep(self._backoff * (2**attempt))
        raise GitLabError(f"GitLab request failed after {self._retries + 1} attempt(s): {last_error}")
