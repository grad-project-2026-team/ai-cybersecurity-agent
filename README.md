# EGYNEXA AI Cybersecurity Agent

Python + FastAPI agent that fetches a developer's PUBLIC GitHub repos, scans them with Semgrep, Gitleaks and OWASP Dependency-Check, adds AI explanations, and writes a structured report per repo (JSON + Markdown). Free and open-source tools only, no paid APIs.

## Status (honest)

| Feature | Status |
|---|---|
| 1. GitHub integration (OAuth + list public repos) | Implemented. Unit-tested with mocks. Live OAuth needs your GitHub OAuth App; NOT tested against real GitHub. |
| 2. Semgrep scanning | Implemented and RUN for real on a local vulnerable fixture (10 findings with Gitleaks). Uses `--config p/default` (`auto` fails when metrics are off; found and fixed during verification). |
| 3. Gitleaks secret detection | Implemented and RUN for real (detected a planted GitHub token). Secrets are redacted in reports. |
| 4. OWASP Dependency-Check | Wrapper + parser implemented, parser unit-tested. NOT verified end to end: without a free NVD API key the first database download (431k records) was too slow to finish here. Get a free key from nvd.nist.gov and set NVD_API_KEY. |
| 5. AI analysis | Implemented: Ollama, optional OpenAI-compatible free-tier adapter, rule-based fallback. Tested with mocked HTTP only; not tested against a real Ollama model. |
| 6. Structured report per developer | Implemented per repo. A combined per-developer rollup is NOT implemented yet. |
| 7. FastAPI backend | Implemented (/health, /auth/github/login, /auth/github/callback, /repos/{user}, /scan/{owner}/{repo}). No auth/rate limiting on our own API yet. |

`examples/example_report.md` is real output from Semgrep + Gitleaks on a small deliberately vulnerable local fixture (not one of your repos). Dependency-Check is shown as not run, and no LLM was used (rule-based fallback).

## Security design
- Repos are cloned shallow, hooks disabled, no submodules, and only read by scanners. Repo code is never executed.
- Owner/repo names are validated before any git call.
- Credentials come from environment variables only (`.env`, git-ignored). The OAuth token is not stored or returned.
- Repo content sent to the AI is treated as data; model output is only parsed as JSON text.

## Install
```
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install semgrep                 # Semgrep
# Gitleaks: https://github.com/gitleaks/gitleaks/releases (put on PATH)
# Dependency-Check CLI: https://owasp.org/www-project-dependency-check/ (put dependency-check.sh on PATH)
# Ollama: https://ollama.com  then:  ollama pull llama3.2
cp .env.example .env                # fill in values
```
GitHub OAuth: create an OAuth App at GitHub > Settings > Developer settings, callback `http://localhost:8000/auth/github/callback`, put the id/secret in `.env`.

## Run
```
export $(grep -v '^#' .env | xargs)
uvicorn app.main:app --reload
# or CLI:  python run_scan.py OWNER REPO
```
Then `POST /scan/{owner}/{repo}`; reports land in `reports/`.

## Test
```
python -m pytest -q
```
To check scanners really work, run `python run_scan.py <owner> <public-repo>` and confirm every tool shows `ok` in the output.
