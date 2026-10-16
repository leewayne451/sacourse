"""Turn logon/logoff pairs into sessions and assign every event to the session it falls in.

A session = one Logon on a PC up to the next Logoff for the same user+PC.
If the Logoff is missing, the session ends at the next Logon or after SESSION_CAP_HOURS.
Events outside any session (e.g. no logon recorded) keep session_id = NULL.
"""
from . import config


def run(con, cap_hours: int = config.SESSION_CAP_HOURS) -> tuple[int, int]:
    cap = int(cap_hours)
    con.execute(f"""
        CREATE OR REPLACE TABLE sessions AS
        WITH l AS (
            SELECT "user", pc, ts, activity, id,
                   LEAD(activity) OVER w AS next_act,
                   LEAD(ts)       OVER w AS next_ts
            FROM logon
            WINDOW w AS (PARTITION BY "user", pc ORDER BY ts, activity DESC, id)
        ), starts AS (
            SELECT * FROM l WHERE activity = 'Logon'
            QUALIFY ROW_NUMBER() OVER (PARTITION BY "user", pc, ts ORDER BY id) = 1
        )
        SELECT 'S' || substr(md5("user" || '|' || pc || '|' || CAST(ts AS VARCHAR)), 1, 10) AS session_id,
               "user", pc,
               ts AS start_ts,
               CASE WHEN next_act = 'Logoff' AND next_ts <= ts + INTERVAL {cap} HOUR THEN next_ts
                    ELSE LEAST(COALESCE(next_ts, ts + INTERVAL {cap} HOUR), ts + INTERVAL {cap} HOUR)
               END AS end_ts,
               COALESCE(next_act = 'Logoff' AND next_ts <= ts + INTERVAL {cap} HOUR, false) AS has_logoff,
               id AS logon_event_id
        FROM starts
        ORDER BY "user", start_ts
    """)
    con.execute("""
        CREATE OR REPLACE TABLE events AS
        WITH m AS (
            SELECT e.id, s.session_id
            FROM events e JOIN sessions s
              ON e."user" = s."user" AND e.pc = s.pc
             AND e.ts >= s.start_ts AND e.ts <= s.end_ts
            QUALIFY ROW_NUMBER() OVER (PARTITION BY e.id ORDER BY s.start_ts DESC) = 1
        )
        SELECT e.* EXCLUDE (session_id), m.session_id
        FROM events e LEFT JOIN m USING (id)
        ORDER BY "user", ts
    """)
    n_sessions = con.execute("SELECT count(*) FROM sessions").fetchone()[0]
    n_assigned = con.execute("SELECT count(*) FROM events WHERE session_id IS NOT NULL").fetchone()[0]
    return n_sessions, n_assigned
