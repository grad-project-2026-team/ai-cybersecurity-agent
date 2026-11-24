from .ai import analyze
from .config import Settings
from .models import RepoReport
from .repo_fetch import cleanup, safe_clone
from .report import save, summarize
from .scanners import run_depcheck, run_gitleaks, run_semgrep


def scan_repo(owner: str, repo: str, cfg: Settings) -> tuple[RepoReport, dict]:
    path = safe_clone(owner, repo, cfg.workdir)
    try:
        findings, status = [], []
        for fn, b in ((run_semgrep, cfg.semgrep_bin), (run_gitleaks, cfg.gitleaks_bin),
                      (run_depcheck, cfg.depcheck_bin)):
            f, s = fn(path, b, cfg.scan_timeout)
            findings += f
            status.append(s)
    finally:
        cleanup(path)
    backend = analyze(findings, cfg)
    rep = RepoReport(repo=f"{owner}/{repo}", clone_url=f"https://github.com/{owner}/{repo}.git",
                     tool_status=status, findings=findings, ai_backend=backend,
                     summary=summarize(findings))
    return rep, save(rep, cfg.report_dir)
