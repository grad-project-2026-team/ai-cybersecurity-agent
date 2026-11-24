"""FastAPI backend (ready for later EGYNEXA integration)."""
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import RedirectResponse

from . import github_client as gh
from .config import load_settings
from .pipeline import scan_repo
from .repo_fetch import FetchError

app = FastAPI(title="EGYNEXA AI Cybersecurity Agent", version="0.1.0")
_STATES: set[str] = set()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/auth/github/login")
def login():
    cfg = load_settings()
    if not cfg.github_client_id:
        raise HTTPException(503, "GitHub OAuth is not configured")
    url, state = gh.authorize_url(cfg.github_client_id, cfg.github_redirect_uri)
    _STATES.add(state)
    return RedirectResponse(url)


@app.get("/auth/github/callback")
def callback(code: str, state: str):
    cfg = load_settings()
    if state not in _STATES:
        raise HTTPException(400, "bad state")
    _STATES.discard(state)
    try:
        token = gh.exchange_code(cfg.github_client_id, cfg.github_client_secret, code)
        login_name = gh.whoami(token)
    except gh.GitHubError as e:
        raise HTTPException(400, str(e))
    # The token is NOT returned or stored. The client lists repos by username.
    return {"authorized_as": login_name}


@app.get("/repos/{username}")
def repos(username: str, x_github_token: str | None = Header(default=None)):
    try:
        return {"repos": gh.list_public_repos(username, x_github_token)}
    except gh.GitHubError as e:
        raise HTTPException(400, str(e))


@app.post("/scan/{owner}/{repo}")
def scan(owner: str, repo: str):
    if not (gh.valid_owner(owner) and gh.valid_repo(repo)):
        raise HTTPException(400, "invalid owner/repo")
    try:
        report, files = scan_repo(owner, repo, load_settings())
    except FetchError as e:
        raise HTTPException(400, str(e))
    return {"report": report.model_dump(), "files": files}
