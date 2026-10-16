"""Session-level behavioural features (+ ground-truth label if answers were loaded).

Each row of `features` is one session. Three kinds of columns:
  * raw counts / times for the session
  * dev_* : deviation from the SAME user's past sessions (past-only window -> no leakage)
  * label / scenario : 1 if the session contains any ground-truth malicious event
"""
from . import config
from .db import table_exists

COUNT_FEATURES = [
    "n_usb_connect", "n_file", "n_file_exec_archive", "n_http", "n_http_leak", "n_http_job",
    "n_http_hack", "n_email", "n_email_external", "n_email_attach", "email_kb",
]
TIME_FEATURES = ["duration_min", "start_hour", "end_hour", "after_hours", "weekend", "foreign_pc"]
DEVIATION_BASE = ["n_usb_connect", "n_file", "n_http", "n_email_external", "n_email_attach",
                  "start_hour", "duration_min"]
DEVIATION_FEATURES = [f"dev_{c}" for c in DEVIATION_BASE]

# What the detector trains on. Add/remove here and every model picks it up.
MODEL_FEATURES = COUNT_FEATURES + TIME_FEATURES + DEVIATION_FEATURES


def run(con) -> int:
    dom = config.ORG_DOMAIN.lower()
    recipients = "lower(coalesce(detail,'') || ';' || coalesce(email_cc,'') || ';' || coalesce(email_bcc,''))"
    deviations = ",\n".join(
        f"""COALESCE(({c} - AVG({c}) OVER u) / NULLIF(STDDEV_SAMP({c}) OVER u, 0), 0) AS dev_{c}"""
        for c in DEVIATION_BASE
    )
    has_labels = table_exists(con, "malicious_events")
    label_sql = (
        """LEFT JOIN (SELECT e.session_id, 1 AS label, min(m.scenario) AS scenario
                      FROM events e JOIN malicious_events m USING (id)
                      WHERE e.session_id IS NOT NULL GROUP BY 1) lab USING (session_id)"""
        if has_labels else ""
    )
    label_cols = ("COALESCE(lab.label, 0) AS label, lab.scenario" if has_labels
                  else "NULL::INTEGER AS label, NULL::VARCHAR AS scenario")

    con.execute(f"""
        CREATE OR REPLACE TABLE features AS
        WITH ev AS (SELECT * FROM events WHERE session_id IS NOT NULL),
        agg AS (
            SELECT session_id,
              count(*) FILTER (WHERE source = 'device' AND activity = 'Connect')            AS n_usb_connect,
              count(*) FILTER (WHERE source = 'file')                                        AS n_file,
              count(*) FILTER (WHERE source = 'file'
                               AND regexp_matches(lower(detail), '\\.(exe|zip|rar|7z|bat|ps1)$')) AS n_file_exec_archive,
              count(*) FILTER (WHERE source = 'http')                                        AS n_http,
              count(*) FILTER (WHERE source = 'http' AND regexp_matches(lower(detail), '{config.LEAK_URL_PATTERN}')) AS n_http_leak,
              count(*) FILTER (WHERE source = 'http' AND regexp_matches(lower(detail), '{config.JOB_URL_PATTERN}'))  AS n_http_job,
              count(*) FILTER (WHERE source = 'http' AND regexp_matches(lower(detail), '{config.HACK_URL_PATTERN}')) AS n_http_hack,
              count(*) FILTER (WHERE source = 'email')                                       AS n_email,
              -- external = some recipient left after removing every @{dom} address
              count(*) FILTER (WHERE source = 'email'
                               AND contains(replace({recipients}, '@{dom}', ''), '@'))       AS n_email_external,
              count(*) FILTER (WHERE source = 'email' AND email_attachments > 0)             AS n_email_attach,
              COALESCE(sum(email_size) FILTER (WHERE source = 'email'), 0) / 1024.0          AS email_kb
            FROM ev GROUP BY session_id
        ),
        main_pc AS (
            SELECT "user", arg_max(pc, n) AS main_pc
            FROM (SELECT "user", pc, count(*) AS n FROM sessions GROUP BY ALL) GROUP BY ALL
        ),
        base AS (
            SELECT s.session_id, s."user", s.pc, s.start_ts, s.end_ts, s.has_logoff,
                   date_diff('minute', s.start_ts, s.end_ts)::DOUBLE      AS duration_min,
                   hour(s.start_ts) + minute(s.start_ts) / 60.0            AS start_hour,
                   hour(s.end_ts) + minute(s.end_ts) / 60.0                AS end_hour,
                   (hour(s.start_ts) < {config.WORK_START_HOUR} OR hour(s.start_ts) >= {config.WORK_END_HOUR}
                    -- only trust the end time when a real Logoff was seen (capped sessions end late)
                    OR (s.has_logoff AND (hour(s.end_ts) >= {config.WORK_END_HOUR}
                                          OR s.end_ts::DATE > s.start_ts::DATE)))::INTEGER AS after_hours,
                   (isodow(s.start_ts) >= 6)::INTEGER                      AS weekend,
                   (s.pc <> p.main_pc)::INTEGER                            AS foreign_pc,
                   {", ".join(f"COALESCE(a.{c}, 0)::DOUBLE AS {c}" for c in COUNT_FEATURES)}
            FROM sessions s
            LEFT JOIN agg a USING (session_id)
            LEFT JOIN main_pc p USING ("user")
        )
        SELECT b.*,
               {deviations},
               {label_cols}
        FROM base b
        {label_sql}
        WINDOW u AS (PARTITION BY b."user" ORDER BY b.start_ts
                     ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING)
        ORDER BY b.start_ts
    """)
    return con.execute("SELECT count(*) FROM features").fetchone()[0]
