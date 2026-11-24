"""Wrappers for Semgrep, Gitleaks and OWASP Dependency-Check.

They only READ the cloned files. Missing tools are reported honestly as
`not_installed` instead of pretending a scan happened.
"""
import json
import os
import shutil
import subprocess
import tempfile

from .models import Finding, ToolStatus

_SEV = {"ERROR": "high", "WARNING": "medium", "INFO": "low",
        "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}


def _run(cmd: list[str], timeout: int):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def redact(s: str) -> str:
    s = (s or "").strip()
    return "[REDACTED]" if len(s) <= 8 else s[:2] + "***REDACTED***" + s[-2:]


def parse_semgrep(data: dict) -> list[Finding]:
    out = []
    for r in data.get("results", []):
        ex = r.get("extra", {})
        sev = _SEV.get(str(ex.get("severity", "")).upper(), "medium")
        out.append(Finding(tool="semgrep", rule_id=r.get("check_id", "unknown"),
                           title=r.get("check_id", "").split(".")[-1] or "semgrep finding",
                           severity=sev, file=r.get("path"),
                           line=(r.get("start") or {}).get("line"),
                           description=ex.get("message", "")))
    return out


def parse_gitleaks(data: list) -> list[Finding]:
    out = []
    for r in data or []:
        out.append(Finding(tool="gitleaks", rule_id=r.get("RuleID", "secret"),
                           title=r.get("Description", "Secret detected"), severity="high",
                           file=r.get("File"), line=r.get("StartLine"),
                           description="Possible hard-coded secret.",
                           evidence=redact(r.get("Secret", ""))))
    return out


def parse_depcheck(data: dict) -> list[Finding]:
    out = []
    for dep in data.get("dependencies", []):
        for v in dep.get("vulnerabilities", []) or []:
            out.append(Finding(tool="dependency-check", rule_id=v.get("name", "CVE"),
                               title=f"{v.get('name', 'CVE')} in {dep.get('fileName', '?')}",
                               severity=_SEV.get(str(v.get("severity", "")).upper(), "medium"),
                               file=dep.get("fileName"),
                               description=(v.get("description") or "")[:500]))
    return out


def run_semgrep(path: str, binary: str, timeout: int):
    if not shutil.which(binary):
        return [], ToolStatus(tool="semgrep", status="not_installed", detail="install: pip install semgrep")
    try:
        p = _run([binary, "scan", "--config", os.environ.get("SEMGREP_CONFIG", "p/default"), "--json", "--quiet", "--metrics=off", path], timeout)
        data = json.loads(p.stdout or "{}")
        return parse_semgrep(data), ToolStatus(tool="semgrep", status="ok")
    except Exception as e:
        return [], ToolStatus(tool="semgrep", status="failed", detail=type(e).__name__)


def run_gitleaks(path: str, binary: str, timeout: int):
    if not shutil.which(binary):
        return [], ToolStatus(tool="gitleaks", status="not_installed", detail="see gitleaks releases")
    rep = os.path.join(tempfile.mkdtemp(), "gl.json")
    try:
        _run([binary, "detect", "--no-git", "--source", path, "--report-format", "json",
              "--report-path", rep, "--exit-code", "0"], timeout)
        data = json.load(open(rep)) if os.path.exists(rep) else []
        return parse_gitleaks(data), ToolStatus(tool="gitleaks", status="ok")
    except Exception as e:
        return [], ToolStatus(tool="gitleaks", status="failed", detail=type(e).__name__)


def run_depcheck(path: str, binary: str, timeout: int):
    if not shutil.which(binary):
        return [], ToolStatus(tool="dependency-check", status="not_installed",
                              detail="see OWASP Dependency-Check CLI")
    outdir = tempfile.mkdtemp()
    try:
        cmd = [binary, "--scan", path, "--format", "JSON", "--out", outdir, "--disableAssembly"]
        if os.environ.get("DEPCHECK_NOUPDATE"):
            cmd.append("--noupdate")
        if os.environ.get("NVD_API_KEY"):
            cmd += ["--nvdApiKey", os.environ["NVD_API_KEY"]]
        _run(cmd, timeout)
        rp = os.path.join(outdir, "dependency-check-report.json")
        data = json.load(open(rp)) if os.path.exists(rp) else {}
        return parse_depcheck(data), ToolStatus(tool="dependency-check", status="ok")
    except Exception as e:
        return [], ToolStatus(tool="dependency-check", status="failed", detail=type(e).__name__)
