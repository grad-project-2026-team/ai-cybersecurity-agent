"""GitHub integration: OAuth authorization + listing PUBLIC repositories."""
import re
import secrets
from urllib.parse import urlencode

import httpx

API = "https://api.github.com"
_NAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
_REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


class GitHubError(Exception):
    pass


def valid_owner(name: str) -> bool:
    return bool(_NAME_RE.match(name))


def valid_repo(name: str) -> bool:
    return bool(_REPO_RE.match(name)) and name not in (".", "..")


def authorize_url(client_id: str, redirect_uri: str) -> tuple[str, str]:
    state = secrets.token_urlsafe(24)
    q = urlencode({"client_id": client_id, "redirect_uri": redirect_uri,
                   "scope": "read:user", "state": state})
    return f"https://github.com/login/oauth/authorize?{q}", state


def exchange_code(client_id: str, client_secret: str, code: str, client: httpx.Client | None = None) -> str:
    c = client or httpx.Client(timeout=20)
    r = c.post("https://github.com/login/oauth/access_token",
               headers={"Accept": "application/json"},
               data={"client_id": client_id, "client_secret": client_secret, "code": code})
    tok = r.json().get("access_token")
    if r.status_code != 200 or not tok:
        raise GitHubError("OAuth code exchange failed")
    return tok


def _headers(token: str | None) -> dict:
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def list_public_repos(username: str, token: str | None = None,
                      client: httpx.Client | None = None, max_pages: int = 5) -> list[dict]:
    """Return public repos of a user. Private repos are never returned."""
    if not valid_owner(username):
        raise GitHubError("invalid GitHub username")
    c = client or httpx.Client(timeout=20)
    out: list[dict] = []
    for page in range(1, max_pages + 1):
        r = c.get(f"{API}/users/{username}/repos", headers=_headers(token),
                  params={"type": "public", "per_page": 100, "page": page})
        if r.status_code == 404:
            raise GitHubError("user not found")
        if r.status_code in (401, 403):
            raise GitHubError("GitHub auth/rate-limit error")
        if r.status_code != 200:
            raise GitHubError(f"GitHub API error {r.status_code}")
        data = r.json()
        for repo in data:
            if repo.get("private") or repo.get("fork") and False:
                continue
            out.append({"name": repo["name"], "full_name": repo["full_name"],
                        "clone_url": repo["clone_url"], "language": repo.get("language"),
                        "description": repo.get("description")})
        if len(data) < 100:
            break
    return out


def whoami(token: str, client: httpx.Client | None = None) -> str:
    c = client or httpx.Client(timeout=20)
    r = c.get(f"{API}/user", headers=_headers(token))
    if r.status_code != 200:
        raise GitHubError("token rejected")
    return r.json()["login"]
