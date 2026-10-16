"""Project-wide settings. Override paths with environment variables if needed."""
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The single DuckDB file every component reads/writes.
DB_PATH = Path(os.environ.get("TRIAGE_DB", ROOT / "work" / "cert.duckdb"))
WORK_DIR = DB_PATH.parent
REPORTS_DIR = WORK_DIR / "reports"

# CERT's fictional company domain; anything else counts as an external email address.
ORG_DOMAIN = os.environ.get("TRIAGE_ORG_DOMAIN", "dtaa.com")

# Office hours used for the after_hours feature (24h clock, [start, end)).
WORK_START_HOUR = 7
WORK_END_HOUR = 19

# A logon with no matching logoff is closed after this many hours.
SESSION_CAP_HOURS = 14

# Keyword lists used by features.py. These are domain-knowledge features: keep them,
# extend them, or drop them and compare -- that is a good ablation for the report.
LEAK_URL_PATTERN = r"wikileaks|leak|pastebin|dropbox|mega\.nz"
JOB_URL_PATTERN = r"job|career|indeed|monster|simplyhired|linkedin|glassdoor|hire"
HACK_URL_PATTERN = r"keylog|spyware|hack|exploit|crack"


def ensure_dirs() -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
