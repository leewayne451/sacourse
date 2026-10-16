"""Load the CERT insider-threat CSVs (and the answers/labels) into DuckDB.

Produces:
  logon, device, http, email, file   raw tables (column `date` parsed into `ts`)
  events                             one narrow table of every event, used by all later stages
  malicious_events                   ids of ground-truth malicious events (from the answers archive)
  insiders                           insiders.csv from the answers archive

Works with headered files (r5+/r6.x) and header-less files; header-less files are
assumed to follow the r4.2 column layout below.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

import pandas as pd

from .db import columns, table_exists

SOURCES = ["logon", "device", "http", "email", "file"]

R42_SCHEMAS = {
    "logon": ["id", "date", "user", "pc", "activity"],
    "device": ["id", "date", "user", "pc", "activity"],
    "http": ["id", "date", "user", "pc", "url", "content"],
    "email": ["id", "date", "user", "pc", "to", "cc", "bcc", "from", "size", "attachments", "content"],
    "file": ["id", "date", "user", "pc", "filename", "content"],
}

# SQL keywords in CERT headers get renamed so nobody has to quote them.
RENAME = {"date": "date_raw", "to": "to_addr", "cc": "cc_addr", "bcc": "bcc_addr", "from": "from_addr"}

DEFAULT_ACTIVITY = {"logon": None, "device": None, "http": "Visit", "email": "Send", "file": "File"}
DETAIL_COLUMN = {"logon": None, "device": None, "http": "url", "email": "to_addr", "file": "filename"}

CERT_DATE_FMT = "%m/%d/%Y %H:%M:%S"

csv.field_size_limit(sys.maxsize)


def _sql_str(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def load_source(con, name: str, path: Path, keep_content: bool = True, lenient: bool = False) -> int:
    with open(path, encoding="utf-8", errors="replace") as fh:
        first = fh.readline()
    has_header = first.lower().startswith("id,")
    if has_header:
        cols = [c.strip().lower() for c in next(csv.reader([first]))]
    else:
        cols = R42_SCHEMAS[name]
        n = len(next(csv.reader([first])))
        if n != len(cols):
            raise ValueError(
                f"{path.name}: no header and {n} columns; expected r4.2 layout {cols}. "
                "Add the right layout to R42_SCHEMAS for this release."
            )
    names = [RENAME.get(c, c) for c in cols]
    excluded = ["id", "date_raw"] + (["content"] if (not keep_content and "content" in names) else [])
    opts = [
        f"header={'true' if has_header else 'false'}",
        "columns={" + ", ".join(f"{_sql_str(n)}: 'VARCHAR'" for n in names) + "}",
        "auto_detect=false", "delim=','", "quote='\"'", "escape='\"'",
        "max_line_size=50000000",
    ]
    if lenient:
        opts.append("ignore_errors=true")
    con.execute(f"""
        CREATE OR REPLACE TABLE {name} AS
        SELECT id, strptime(date_raw, '{CERT_DATE_FMT}') AS ts,
               * EXCLUDE ({', '.join(excluded)})
        FROM read_csv({_sql_str(path)}, {', '.join(opts)})
    """)
    return con.execute(f"SELECT count(*) FROM {name}").fetchone()[0]


def build_events(con) -> int:
    """One narrow table over all sources. `detail` = url / filename / email recipients."""
    parts = []
    for src in SOURCES:
        if not table_exists(con, src):
            continue
        cols = columns(con, src)
        activity = "activity" if "activity" in cols else _sql_str(DEFAULT_ACTIVITY[src])
        detail = DETAIL_COLUMN[src] if DETAIL_COLUMN[src] in cols else "NULL"
        if src == "email":
            email = (
                "cc_addr AS email_cc, bcc_addr AS email_bcc, from_addr AS email_from, "
                "TRY_CAST(size AS BIGINT) AS email_size, "
                "COALESCE(TRY_CAST(attachments AS INTEGER), "
                "  CASE WHEN attachments IS NULL OR trim(attachments) = '' THEN 0 "
                "       ELSE len(string_split(attachments, ';')) END) AS email_attachments"
            )
        else:
            email = ("NULL::VARCHAR AS email_cc, NULL::VARCHAR AS email_bcc, NULL::VARCHAR AS email_from, "
                     "NULL::BIGINT AS email_size, NULL::INTEGER AS email_attachments")
        parts.append(
            f"SELECT id, '{src}' AS source, ts, \"user\", pc, {activity}::VARCHAR AS activity, "
            f"{detail}::VARCHAR AS detail, {email} FROM {src}"
        )
    if not parts:
        raise RuntimeError("No source tables loaded.")
    con.execute(
        "CREATE OR REPLACE TABLE events AS SELECT *, NULL::VARCHAR AS session_id FROM ("
        + " UNION ALL ".join(parts) + ") ORDER BY \"user\", ts"
    )
    return con.execute("SELECT count(*) FROM events").fetchone()[0]


def load_answers(con, answers_dir: Path, release: str | None = "r4.2") -> tuple[int, int]:
    """Parse the CERT answers archive (extracted). Returns (#malicious events, #insiders)."""
    rel = release.lstrip("rR") if release else None
    events, insiders = [], []
    for p in sorted(Path(answers_dir).rglob("*.csv")):
        if p.name.lower() == "insiders.csv":
            with open(p, newline="", encoding="utf-8", errors="replace") as fh:
                for row in csv.DictReader(fh):
                    ds = str(row.get("dataset", "")).lstrip("rR")
                    if rel is None or ds == rel or _float_eq(ds, rel):
                        insiders.append(row)
            continue
        folder = p.parent.name  # e.g. r4.2-1
        if rel is not None and not folder.lower().startswith(f"r{rel}-"):
            continue
        scenario = folder.rsplit("-", 1)[-1] if "-" in folder else None
        with open(p, newline="", encoding="utf-8", errors="replace") as fh:
            for row in csv.reader(fh):
                if len(row) >= 2 and row[0].strip().lower() in SOURCES:
                    events.append({
                        "id": row[1].strip(),
                        "source": row[0].strip().lower(),
                        "user": row[3].strip() if len(row) > 3 else None,
                        "scenario": scenario,
                        "answer_file": p.name,
                    })
    ev = pd.DataFrame(events, columns=["id", "source", "user", "scenario", "answer_file"]).drop_duplicates("id")
    ins = pd.DataFrame(insiders)
    con.register("ev_df", ev)
    con.execute("CREATE OR REPLACE TABLE malicious_events AS SELECT * FROM ev_df")
    con.unregister("ev_df")
    if not ins.empty:
        con.register("ins_df", ins)
        con.execute("CREATE OR REPLACE TABLE insiders AS SELECT * FROM ins_df")
        con.unregister("ins_df")
    return len(ev), len(ins)


def _float_eq(a: str, b: str) -> bool:
    try:
        return float(a) == float(b)
    except ValueError:
        return False


def run(con, cert_dir: Path, answers_dir: Path | None = None, release: str | None = "r4.2",
        keep_content: bool = True, lenient: bool = False) -> None:
    cert_dir = Path(cert_dir)
    for src in SOURCES:
        path = cert_dir / f"{src}.csv"
        if not path.exists():
            print(f"  [skip] {path} not found")
            continue
        n = load_source(con, src, path, keep_content=keep_content, lenient=lenient)
        print(f"  {src:<7} {n:>12,} rows")
    n = build_events(con)
    print(f"  events  {n:>12,} rows")
    if answers_dir:
        ne, ni = load_answers(con, Path(answers_dir), release)
        print(f"  answers {ne:>12,} malicious events, {ni} insiders")
        missing = con.execute(
            "SELECT count(*) FROM malicious_events m ANTI JOIN events e USING (id)"
        ).fetchone()[0]
        if missing:
            print(f"  [warn] {missing} answer ids not found in events (wrong release or partial load?)")
