"""CLI: python run_scan.py OWNER REPO"""
import sys

from app.config import load_settings
from app.pipeline import scan_repo

if len(sys.argv) != 3:
    sys.exit("usage: python run_scan.py OWNER REPO")
rep, files = scan_repo(sys.argv[1], sys.argv[2], load_settings())
print(rep.summary, files)
for t in rep.tool_status:
    print(t.tool, t.status, t.detail)
