"""Demo UI:  streamlit run app/demo.py

Pick an alert -> run (or load) the investigation -> see every claim marked
verified / unsupported / interpretive, with the raw log rows it cites.
"""
import sys
from pathlib import Path

import pandas as pd
import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from triage import config, db  # noqa: E402
from triage.agent.investigate import MockInvestigator, investigate, load_report, save_report  # noqa: E402
from triage.agent.llm import OpenAICompatLLM  # noqa: E402
from triage.verifier.verify import fetch_events, verify_report  # noqa: E402

st.set_page_config(page_title="Insider Triage", layout="wide")


@st.cache_resource
def get_con():
    return db.connect(read_only=True)


con = get_con()
if not db.table_exists(con, "alerts"):
    st.error("No alerts table yet. Run the pipeline first (see README).")
    st.stop()

alerts = con.execute(
    'SELECT rank, session_id, "user", pc, start_ts, round(score, 4) AS score, label FROM alerts ORDER BY rank'
).df()

with st.sidebar:
    st.header("Alerts")
    show_truth = st.toggle("Show ground truth (evaluation only)", value=False)
    labels = [f"#{r.rank}  {r.user}  {r.start_ts:%Y-%m-%d %H:%M}"
              + (("  [INSIDER]" if r.label == 1 else "") if show_truth else "")
              for r in alerts.itertuples()]
    idx = st.radio("Flagged sessions", range(len(alerts)), format_func=lambda i: labels[i], label_visibility="collapsed")

alert = alerts.iloc[idx]
sid = alert.session_id
st.title("Insider-threat triage")
c1, c2, c3, c4 = st.columns(4)
c1.metric("User", alert.user)
c2.metric("PC", alert.pc)
c3.metric("Session start", f"{alert.start_ts:%Y-%m-%d %H:%M}")
c4.metric("Anomaly score (rank)", f"{alert.score} (#{alert['rank']})")

report_path = config.REPORTS_DIR / f"{sid}.json"
b1, b2, b3 = st.columns(3)
if b1.button("Run mock agent"):
    rep, trace = MockInvestigator().investigate(con, sid)
    save_report(rep, trace, "mock")
if b2.button("Mock agent + 2 hallucinations"):
    rep, trace = MockInvestigator(hallucinate=2, seed=idx).investigate(con, sid)
    save_report(rep, trace, "mock(hallucinate=2)")
if b3.button("Run LLM agent"):
    llm = OpenAICompatLLM()
    with st.spinner(f"Investigating with {llm.describe()} ..."):
        try:
            rep, trace = investigate(con, sid, llm)
            save_report(rep, trace, llm.describe())
        except Exception as e:
            st.error(f"LLM run failed: {e}")

tab_report, tab_events = st.tabs(["Verified report", "All session events"])

with tab_report:
    if not report_path.exists():
        st.info("No report for this session yet. Run an agent above.")
    else:
        report = load_report(report_path)
        res = verify_report(con, report)
        s = res["summary"]
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Verified", s["verified"])
        m2.metric("Unsupported", s["unsupported"])
        m3.metric("Interpretive", s["interpretive"])
        m4.metric("Groundedness", "-" if s["groundedness"] is None else f"{s['groundedness']:.0%}")
        st.markdown(f"**Agent verdict:** `{report.verdict}`  \n{report.summary}")
        cited = fetch_events(con, [c for cl in report.claims for c in cl.citations])
        for c in res["claims"]:
            box = {"verified": st.success, "unsupported": st.error, "interpretive": st.info}[c["status"]]
            box(f"**{c['status'].upper()}** · {c['text']}")
            if c["reasons"] or c["warnings"] or c["citations"]:
                with st.expander(f"Evidence for claim {c['index'] + 1}"):
                    for r in c["reasons"]:
                        st.markdown(f"- ❌ {r}")
                    for w in c["warnings"]:
                        st.markdown(f"- ⚠️ {w}")
                    rows = [cited[x] for x in c["citations"] if x in cited]
                    if rows:
                        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")
                    missing = [x for x in c["citations"] if x not in cited]
                    if missing:
                        st.markdown("Cited ids not found in the logs: " + ", ".join(f"`{m}`" for m in missing))

with tab_events:
    ev = con.execute(
        "SELECT ts, source, activity, detail, id FROM events WHERE session_id = ? ORDER BY ts", [sid]).df()
    st.dataframe(ev, hide_index=True, width="stretch")
