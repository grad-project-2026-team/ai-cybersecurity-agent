import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    github_client_id: str
    github_client_secret: str
    github_redirect_uri: str
    ollama_url: str
    ollama_model: str
    free_api_url: str
    free_api_key: str
    free_api_model: str
    semgrep_bin: str
    gitleaks_bin: str
    depcheck_bin: str
    workdir: str
    report_dir: str
    scan_timeout: int


def load_settings() -> Settings:
    """Read settings from environment variables only (no secrets in code)."""
    g = os.environ.get
    return Settings(
        github_client_id=g("GITHUB_CLIENT_ID", ""),
        github_client_secret=g("GITHUB_CLIENT_SECRET", ""),
        github_redirect_uri=g("GITHUB_REDIRECT_URI", "http://localhost:8000/auth/github/callback"),
        ollama_url=g("OLLAMA_URL", "http://localhost:11434"),
        ollama_model=g("OLLAMA_MODEL", "llama3.2"),
        free_api_url=g("FREE_API_URL", ""),
        free_api_key=g("FREE_API_KEY", ""),
        free_api_model=g("FREE_API_MODEL", ""),
        semgrep_bin=g("SEMGREP_BIN", "semgrep"),
        gitleaks_bin=g("GITLEAKS_BIN", "gitleaks"),
        depcheck_bin=g("DEPCHECK_BIN", "dependency-check.sh"),
        workdir=g("WORKDIR", "./workdir"),
        report_dir=g("REPORT_DIR", "./reports"),
        scan_timeout=int(g("SCAN_TIMEOUT_SECONDS", "600")),
    )
