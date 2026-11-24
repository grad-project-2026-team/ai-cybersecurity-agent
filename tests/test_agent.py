import httpx
import pytest
from fastapi.testclient import TestClient

from app import github_client as gh
from app.ai import analyze
from app.config import load_settings
from app.main import app
from app.models import Finding
from app.repo_fetch import FetchError, safe_clone
from app.report import summarize, to_markdown
from app.models import RepoReport
from app.scanners import parse_depcheck, parse_gitleaks, parse_semgrep, redact


def test_parse_semgrep():
    f = parse_semgrep({"results": [{"check_id": "a.b.sqli", "path": "x.py",
                                    "start": {"line": 3}, "extra": {"severity": "ERROR", "message": "m"}}]})
    assert f[0].severity == "high" and f[0].line == 3


def test_gitleaks_redacts_secret():
    f = parse_gitleaks([{"RuleID": "aws", "File": "a", "StartLine": 1, "Secret": "AKIAABCDEFGHIJKLMNOP"}])
    assert "ABCDEFGH" not in f[0].evidence and "REDACTED" in f[0].evidence
    assert redact("short") == "[REDACTED]"


def test_depcheck():
    f = parse_depcheck({"dependencies": [{"fileName": "l.jar", "vulnerabilities": [
        {"name": "CVE-1", "severity": "CRITICAL", "description": "d"}]}]})
    assert f[0].severity == "critical"


def test_ai_fallback_when_no_backend(monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "")
    fs = [Finding(tool="gitleaks", rule_id="r", title="t", severity="high")]
    assert analyze(fs, load_settings()) == "rule-based-fallback"
    assert fs[0].ai_fix and fs[0].ai_severity == "high"


def test_ai_ollama_mock(monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    def h(req):
        return httpx.Response(200, json={"response": '{"explanation":"e","severity":"low","fix":"f"}'})
    c = httpx.Client(transport=httpx.MockTransport(h))
    fs = [Finding(tool="semgrep", rule_id="r", title="t", severity="high")]
    assert analyze(fs, load_settings(), client=c) == "ollama"
    assert fs[0].ai_severity == "low"


def test_ai_bad_json_falls_back(monkeypatch):
    monkeypatch.setenv("OLLAMA_URL", "http://localhost:11434")
    c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"response": "nope"})))
    fs = [Finding(tool="semgrep", rule_id="r", title="t", severity="high")]
    assert analyze(fs, load_settings(), client=c) == "rule-based-fallback"


def test_list_public_repos_filters_private():
    def h(req):
        return httpx.Response(200, json=[
            {"name": "a", "full_name": "u/a", "clone_url": "x", "private": False},
            {"name": "b", "full_name": "u/b", "clone_url": "y", "private": True}])
    c = httpx.Client(transport=httpx.MockTransport(h))
    assert [r["name"] for r in gh.list_public_repos("u", client=c)] == ["a"]


def test_list_repos_errors():
    c = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(404)))
    with pytest.raises(gh.GitHubError):
        gh.list_public_repos("nobody", client=c)
    with pytest.raises(gh.GitHubError):
        gh.list_public_repos("bad name;rm", client=c)


def test_clone_rejects_bad_names(tmp_path):
    for o, r in (("a/../b", "r"), ("o", "--upload-pack=x"), ("o", "..")):
        with pytest.raises(FetchError):
            safe_clone(o, r, str(tmp_path))


def test_report_markdown_and_honesty():
    from app.models import ToolStatus
    r = RepoReport(repo="o/r", clone_url="u", ai_backend="x",
                   tool_status=[ToolStatus(tool="semgrep", status="not_installed")],
                   findings=[], summary=summarize([]))
    md = to_markdown(r)
    assert "not_installed" in md and "did NOT scan" in md


def test_api_health_and_validation():
    c = TestClient(app)
    assert c.get("/health").json() == {"status": "ok"}
    assert c.post("/scan/bad;owner/repo").status_code in (400, 404)
    assert c.get("/auth/github/login").status_code == 503
    assert c.get("/auth/github/callback", params={"code": "c", "state": "s"}).status_code == 400
