from typing import Optional
from pydantic import BaseModel


class Finding(BaseModel):
    tool: str                      # semgrep | gitleaks | dependency-check
    rule_id: str
    title: str
    severity: str                  # critical | high | medium | low | info
    file: Optional[str] = None
    line: Optional[int] = None
    description: str = ""
    # Never store the secret value itself, only a redacted hint.
    evidence: str = ""
    ai_explanation: str = ""
    ai_fix: str = ""
    ai_severity: str = ""          # AI classification (may differ from tool's)


class ToolStatus(BaseModel):
    tool: str
    status: str                    # ok | not_installed | failed | skipped
    detail: str = ""


class RepoReport(BaseModel):
    repo: str
    clone_url: str
    tool_status: list[ToolStatus]
    findings: list[Finding]
    ai_backend: str
    summary: dict
