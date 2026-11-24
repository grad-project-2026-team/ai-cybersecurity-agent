"""Safely fetch a repository for static scanning. Code is NEVER executed."""
import os
import shutil
import subprocess

from .github_client import valid_owner, valid_repo


class FetchError(Exception):
    pass


def safe_clone(owner: str, repo: str, workdir: str, timeout: int = 300) -> str:
    if not (valid_owner(owner) and valid_repo(repo)):
        raise FetchError("invalid owner/repo name")
    dest = os.path.abspath(os.path.join(workdir, f"{owner}__{repo}"))
    if not dest.startswith(os.path.abspath(workdir) + os.sep):
        raise FetchError("path escape")
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(workdir, exist_ok=True)
    url = f"https://github.com/{owner}/{repo}.git"   # https only, built by us
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.file.allow=never",
           "-c", "core.fsmonitor=false", "clone", "--depth", "1",
           "--no-recurse-submodules", "--single-branch", url, dest]
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        raise FetchError("clone timed out")
    if p.returncode != 0:
        raise FetchError("clone failed (repo missing or not public)")
    return dest


def cleanup(path: str) -> None:
    shutil.rmtree(path, ignore_errors=True)
