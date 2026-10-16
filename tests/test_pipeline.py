"""End-to-end tests on the synthetic sample. Run: pytest -q"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from make_sample_data import build  # noqa: E402
from triage import db, detect, features, ingest, sessions  # noqa: E402
from triage.agent.investigate import MockInvestigator, investigate  # noqa: E402
from triage.agent.schema import Claim, Report  # noqa: E402
from triage.verifier.verify import check_field, verify_report  # noqa: E402


@pytest.fixture(scope="session")
def con(tmp_path_factory):
    d = tmp_path_factory.mktemp("cert")
    build(d, n_users=15, n_days=110, seed=3)
    c = db.connect(d / "t.duckdb")
    ingest.run(c, d / "r4.2", d / "answers", "r4.2")
    sessions.run(c)
    features.run(c)
    detect.run(c, detect.DetectConfig(models=("iforest",), top_k=30))
    return c


def test_answers_join_events(con):
    missing = con.execute("SELECT count(*) FROM malicious_events ANTI JOIN events USING (id)").fetchone()[0]
    assert missing == 0
    assert con.execute("SELECT sum(label) FROM features").fetchone()[0] > 0


def test_every_event_in_at_most_one_session(con):
    dup = con.execute("SELECT count(*) - count(DISTINCT id) FROM events").fetchone()[0]
    assert dup == 0


def test_detector_ranks_insiders_high(con):
    top = con.execute("SELECT count(DISTINCT \"user\") FROM alerts WHERE label = 1").fetchone()[0]
    assert top >= 2


def _top_session(con):
    return con.execute("SELECT session_id FROM alerts ORDER BY rank LIMIT 1").fetchone()[0]


def test_mock_report_fully_verified(con):
    rep, _ = MockInvestigator().investigate(con, _top_session(con))
    res = verify_report(con, rep)
    assert res["summary"]["unsupported"] == 0
    assert res["summary"]["verified"] >= 1


def test_hallucinations_are_caught(con):
    rep, _ = MockInvestigator(hallucinate=3, seed=1).investigate(con, _top_session(con))
    res = verify_report(con, rep)
    assert res["summary"]["unsupported"] == 3


def test_check_field_rules():
    ev = {"id": "x", "source": "email", "date": "2010-03-01 22:14:05", "user": "U", "pc": "PC-1",
          "activity": "Send", "to": "a@dtaa.com;b@gmail.com", "cc": "", "bcc": "", "from": "U@dtaa.com",
          "size": 1234, "attachments": 2}
    assert check_field(ev, "date", "2010-03-01 22:14") is None          # minute precision
    assert check_field(ev, "date", "2010-03-01") is None                # day precision
    assert check_field(ev, "date", "2010-03-01 22:15") is not None
    assert check_field(ev, "time", "22:14") is None
    assert check_field(ev, "to", "b@gmail.com") is None                 # one of the recipients
    assert check_field(ev, "to_contains", "gmail") is None
    assert check_field(ev, "attachments", 2) is None
    assert check_field(ev, "attachments", "3") is not None
    assert check_field(ev, "url", "http://x") is not None               # wrong source for field
    assert check_field(ev, "colour", "red") is not None                 # unknown field


def test_factual_claim_needs_checkable_content(con):
    sid = _top_session(con)
    eid = con.execute("SELECT id FROM events WHERE session_id = ? LIMIT 1", [sid]).fetchone()[0]
    rep = Report(session_id=sid, claims=[
        Claim(text="The user uploaded secrets to wikileaks.", type="factual", citations=[eid])])
    assert verify_report(con, rep)["claims"][0]["status"] == "unsupported"


class ScriptedLLM:
    """Plays back fixed responses: one tool call, then a final report citing a real event."""

    def __init__(self, event):
        self.event, self.calls = event, 0

    def chat(self, messages):
        self.calls += 1
        if self.calls == 1:
            return json.dumps({"action": "tool", "tool": "get_user_baseline",
                               "args": {"user": self.event["user"], "before": self.event["date"]}})
        assert "TOOL RESULT" in messages[-1]["content"]
        e = self.event
        return "```json\n" + json.dumps({"action": "final", "report": {
            "verdict": "suspicious", "summary": "test",
            "claims": [
                {"text": f"Logged on to {e['pc']} at {e['date']}", "type": "factual", "citations": [e["id"]],
                 "asserted": {"source": "logon", "pc": e["pc"], "date": e["date"]}},
                {"text": "Unusual for this user", "type": "interpretive"},
            ]}}) + "\n```"


def test_llm_loop_with_scripted_model(con):
    from triage.agent.tools import Tools
    sid = _top_session(con)
    logon = [e for e in Tools(con).get_session_events(sid) if e["source"] == "logon"][0]
    rep, trace = investigate(con, sid, ScriptedLLM(logon))
    assert trace[0]["tool"] == "get_user_baseline"
    res = verify_report(con, rep)
    assert [c["status"] for c in res["claims"]] == ["verified", "interpretive"]
