"""Read-only tools the investigation agent can call. Every event returned carries its `id`,
which is what the agent must cite."""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any

EVENT_COLS = 'id, source, ts, "user", pc, activity, detail, email_cc, email_bcc, email_from, email_size, email_attachments'


def _row_to_event(cols: list[str], row: tuple) -> dict:
    d = dict(zip(cols, row))
    out = {
        "id": d["id"], "source": d["source"],
        "date": d["ts"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(d["ts"], datetime) else str(d["ts"]),
        "user": d["user"], "pc": d["pc"], "activity": d["activity"],
    }
    if d["source"] == "http":
        out["url"] = d["detail"]
    elif d["source"] == "file":
        out["filename"] = d["detail"]
    elif d["source"] == "email":
        out.update({"to": d["detail"], "cc": d["email_cc"] or "", "bcc": d["email_bcc"] or "",
                    "from": d["email_from"], "size": d["email_size"], "attachments": d["email_attachments"]})
    return out


class Tools:
    SPEC = {
        "get_session_events": {
            "description": "Events inside a session, oldest first. Filter by source to page through busy sessions.",
            "args": {"session_id": "str", "source": "optional: logon|device|http|email|file",
                     "limit": "int, default 100", "offset": "int, default 0"},
        },
        "get_user_baseline": {
            "description": "The user's typical behaviour over the 30 days before a timestamp "
                           "(averages per session, usual hours, usual PC).",
            "args": {"user": "str", "before": "timestamp 'YYYY-MM-DD HH:MM:SS'"},
        },
        "search_user_events": {
            "description": "Search one user's events in a time range (any session).",
            "args": {"user": "str", "start": "timestamp", "end": "timestamp",
                     "source": "optional", "contains": "optional substring of url/filename/recipient",
                     "limit": "int, default 50"},
        },
        "get_events": {
            "description": "Fetch specific events by id.",
            "args": {"ids": "list of event ids"},
        },
    }

    def __init__(self, con):
        self.con = con

    # -- helpers ---------------------------------------------------------------------------
    def _events(self, where: str, params: list, limit: int = 100, offset: int = 0) -> list[dict]:
        cur = self.con.execute(
            f"SELECT {EVENT_COLS} FROM events WHERE {where} ORDER BY ts, id LIMIT ? OFFSET ?",
            params + [int(limit), int(offset)],
        )
        cols = [c[0] for c in cur.description]
        return [_row_to_event(cols, r) for r in cur.fetchall()]

    # -- tools -----------------------------------------------------------------------------
    def get_session(self, session_id: str) -> dict:
        cur = self.con.execute("SELECT * FROM features WHERE session_id = ?", [session_id])
        row = cur.fetchone()
        if row is None:
            raise KeyError(f"unknown session {session_id}")
        d = dict(zip([c[0] for c in cur.description], row))
        d.pop("label", None)          # never show ground truth to the agent
        d.pop("scenario", None)
        counts = dict(self.con.execute(
            "SELECT source, count(*) FROM events WHERE session_id = ? GROUP BY 1", [session_id]).fetchall())
        d["event_counts"] = counts
        return {k: (v.strftime("%Y-%m-%d %H:%M:%S") if isinstance(v, datetime) else v) for k, v in d.items()}

    def get_session_events(self, session_id: str, source: str | None = None,
                           limit: int = 100, offset: int = 0) -> list[dict]:
        where, params = "session_id = ?", [session_id]
        if source:
            where += " AND source = ?"
            params.append(source)
        return self._events(where, params, limit, offset)

    def get_user_baseline(self, user: str, before: str, days: int = 30) -> dict:
        end = datetime.fromisoformat(str(before))
        start = end - timedelta(days=days)
        cur = self.con.execute("""
            SELECT count(*) AS sessions,
                   round(avg(start_hour), 2) AS avg_start_hour, round(avg(end_hour), 2) AS avg_end_hour,
                   round(avg(after_hours), 3) AS frac_after_hours,
                   round(avg(n_usb_connect), 3) AS avg_usb_connects, round(avg(n_file), 3) AS avg_files,
                   round(avg(n_http), 2) AS avg_http, round(avg(n_http_job), 3) AS avg_job_site_visits,
                   round(avg(n_email_external), 3) AS avg_external_emails,
                   mode(pc) AS usual_pc
            FROM features WHERE "user" = ? AND start_ts >= ? AND start_ts < ?
        """, [user, start, end])
        d = dict(zip([c[0] for c in cur.description], cur.fetchone()))
        d.update({"user": user, "window": f"{start:%Y-%m-%d} to {end:%Y-%m-%d}"})
        return d

    def search_user_events(self, user: str, start: str, end: str, source: str | None = None,
                           contains: str | None = None, limit: int = 50) -> list[dict]:
        where, params = '"user" = ? AND ts >= ? AND ts <= ?', [user, start, end]
        if source:
            where += " AND source = ?"
            params.append(source)
        if contains:
            where += " AND contains(lower(coalesce(detail, '')), lower(?))"
            params.append(contains)
        return self._events(where, params, limit)

    def get_events(self, ids: list[str]) -> list[dict]:
        if not ids:
            return []
        return self._events("id IN (SELECT unnest(?::VARCHAR[]))", [list(ids)], limit=len(ids))

    # -- dispatch --------------------------------------------------------------------------
    def call(self, name: str, args: dict[str, Any]) -> Any:
        if name not in self.SPEC:
            return {"error": f"unknown tool '{name}'. Available: {list(self.SPEC)}"}
        try:
            return getattr(self, name)(**(args or {}))
        except Exception as e:  # report errors back to the model instead of crashing
            return {"error": f"{type(e).__name__}: {e}"}

    def spec_text(self) -> str:
        return json.dumps(self.SPEC, indent=2)
