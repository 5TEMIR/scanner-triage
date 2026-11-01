import io
import json
import urllib.error

import pytest

from triage.gitlab import GitLabClient, GitLabError
from triage.models import Finding


class FakeResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload

    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return json.dumps(self._payload).encode()


def test_issue_is_created(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []

    def fake_urlopen(request, timeout):  # noqa: ANN001
        calls.append((request, timeout))
        return FakeResponse({"iid": 17})

    monkeypatch.setattr("triage.gitlab.urllib.request.urlopen", fake_urlopen)
    client = GitLabClient("https://gitlab.example", "secret-token", 42)
    issue = client.create_issue(Finding("trivy", "CVE-1", "title", "HIGH", "image"))

    assert issue == {"iid": 17}
    request, timeout = calls[0]
    assert request.full_url == "https://gitlab.example/api/v4/projects/42/issues"
    assert timeout == 10.0
    assert request.get_header("Private-token") == "secret-token"


def test_retry_on_server_error(monkeypatch: pytest.MonkeyPatch) -> None:
    responses = [
        urllib.error.HTTPError("url", 503, "busy", {}, io.BytesIO(b"")),
        FakeResponse({"iid": 1}),
    ]

    def fake_urlopen(request, timeout):  # noqa: ANN001
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result

    sleeps: list[float] = []
    monkeypatch.setattr("triage.gitlab.urllib.request.urlopen", fake_urlopen)
    client = GitLabClient("https://gitlab.example", "t", 1, retries=2, backoff=0.5, sleep=sleeps.append)

    assert client.create_issue(Finding("trivy", "CVE-1", "t", "HIGH", "img")) == {"iid": 1}
    assert sleeps == [0.5]


def test_client_error_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    attempts = []

    def fake_urlopen(request, timeout):  # noqa: ANN001
        attempts.append(request)
        raise urllib.error.HTTPError("url", 401, "unauthorized", {}, io.BytesIO(b""))

    monkeypatch.setattr("triage.gitlab.urllib.request.urlopen", fake_urlopen)
    client = GitLabClient("https://gitlab.example", "t", 1, retries=3, sleep=lambda _: None)

    with pytest.raises(GitLabError, match="HTTP 401"):
        client.create_issue(Finding("trivy", "CVE-1", "t", "HIGH", "img"))
    assert len(attempts) == 1


def test_token_is_not_leaked_in_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(request, timeout):  # noqa: ANN001
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("triage.gitlab.urllib.request.urlopen", fake_urlopen)
    client = GitLabClient("https://gitlab.example", "super-secret", 1, retries=0)

    with pytest.raises(GitLabError) as exc:
        client.create_issue(Finding("trivy", "CVE-1", "t", "HIGH", "img"))
    assert "super-secret" not in str(exc.value)


def test_empty_token_is_rejected() -> None:
    with pytest.raises(ValueError):
        GitLabClient("https://gitlab.example", "", 1)


def test_non_http_scheme_is_rejected() -> None:
    with pytest.raises(ValueError, match="http"):
        GitLabClient("file:///etc/passwd", "t", 1)


def test_relative_url_is_rejected() -> None:
    with pytest.raises(ValueError, match="http"):
        GitLabClient("gitlab.example", "t", 1)
