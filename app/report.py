import json
import os
from collections import Counter

from .models import RepoReport

ORDER = ["critical", "high", "medium", "low", "info"]


def summarize(findings) -> dict:
    c = Counter(f.ai_severity or f.severity for f in findings)
    return {"total": len(findings), **{k: c.get(k, 0) for k in ORDER}}


def to_markdown(r: RepoReport) -> str:
    L = [f"# Security Report: {r.repo}", "", f"AI backend: `{r.ai_backend}`", "",
         "## Summary", "", "| Severity | Count |", "|---|---|"]
    L += [f"| {k} | {r.summary.get(k, 0)} |" for k in ORDER]
    L += ["", f"Total findings: {r.summary['total']}", "", "## Tool status", ""]
    L += [f"- {t.tool}: **{t.status}** {t.detail}" for t in r.tool_status]
    L += ["", "> A tool marked not_installed/failed did NOT scan. Absence of findings from it means nothing.", "",
          "## Findings", ""]
    fs = sorted(r.findings, key=lambda f: ORDER.index(f.ai_severity or f.severity)
                if (f.ai_severity or f.severity) in ORDER else 9)
    if not fs:
        L.append("No findings from the tools that ran.")
    for i, f in enumerate(fs, 1):
        L += [f"### {i}. [{(f.ai_severity or f.severity).upper()}] {f.title}",
              f"- Tool: {f.tool} | Rule: `{f.rule_id}`",
              f"- Location: {f.file}:{f.line}" if f.file else "- Location: n/a"]
        if f.evidence:
            L.append(f"- Evidence (redacted): `{f.evidence}`")
        L += [f"- Why it matters: {f.ai_explanation}", f"- Recommended fix: {f.ai_fix}", ""]
    return "\n".join(L)


def save(r: RepoReport, report_dir: str) -> dict:
    os.makedirs(report_dir, exist_ok=True)
    base = os.path.join(report_dir, r.repo.replace("/", "__"))
    with open(base + ".json", "w") as fh:
        json.dump(r.model_dump(), fh, indent=2)
    with open(base + ".md", "w") as fh:
        fh.write(to_markdown(r))
    return {"json": base + ".json", "markdown": base + ".md"}
