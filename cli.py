"""Command-line entry point. Run `python cli.py -h` or `python cli.py <command> -h`."""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from triage import config, db


def cmd_sample_data(a):
    sys.path.insert(0, str(config.ROOT / "scripts"))
    from make_sample_data import build
    build(Path(a.out), a.users, a.days, a.seed)


def cmd_ingest(a):
    from triage import ingest
    con = db.connect(a.db)
    t = time.time()
    ingest.run(con, Path(a.cert_dir), Path(a.answers_dir) if a.answers_dir else None, a.release,
               keep_content=not a.no_content, lenient=a.lenient)
    print(f"done in {time.time() - t:.1f}s -> {a.db or config.DB_PATH}")


def cmd_sessions(a):
    from triage import sessions
    n, m = sessions.run(db.connect(a.db), a.cap_hours)
    print(f"  {n:,} sessions, {m:,} events assigned to a session")


def cmd_features(a):
    from triage import features
    con = db.connect(a.db)
    n = features.run(con)
    lab = con.execute("SELECT sum(label) FROM features").fetchone()[0]
    print(f"  {n:,} session feature rows" + (f", {int(lab)} labelled malicious" if lab is not None else ""))


def cmd_detect(a):
    from triage import detect
    cfg = detect.DetectConfig(train_frac=a.train_frac, models=tuple(a.models), primary=a.primary,
                              top_k=a.top_k, train_benign_only=a.train_benign_only)
    detect.run(db.connect(a.db), cfg)
    print(f"  alerts table = top {a.top_k} by {a.primary}; metrics in {config.WORK_DIR / 'detector_metrics.json'}")


def _session_ids(con, a) -> list[str]:
    if a.session:
        return a.session
    return [r[0] for r in con.execute("SELECT session_id FROM alerts ORDER BY rank LIMIT ?", [a.top]).fetchall()]


def cmd_investigate(a):
    from triage.agent.investigate import MockInvestigator, investigate, save_report
    from triage.agent.llm import OpenAICompatLLM
    con = db.connect(a.db, read_only=True)
    ids = _session_ids(con, a)
    if a.backend == "mock":
        agent, label = MockInvestigator(hallucinate=a.hallucinate), f"mock(hallucinate={a.hallucinate})"
    else:
        llm = OpenAICompatLLM(model=a.model, base_url=a.base_url)
        label = llm.describe()
    for sid in ids:
        t = time.time()
        try:
            rep, trace = agent.investigate(con, sid) if a.backend == "mock" else investigate(con, sid, llm, a.max_steps)
        except Exception as e:
            print(f"  {sid}: FAILED {type(e).__name__}: {e}")
            continue
        p = save_report(rep, trace, label)
        print(f"  {sid}: {len(rep.claims)} claims, verdict={rep.verdict} ({time.time() - t:.1f}s) -> {p.name}")


def cmd_verify(a):
    from triage.agent.investigate import load_report
    from triage.verifier.verify import verify_report
    con = db.connect(a.db, read_only=True)
    paths = ([config.REPORTS_DIR / f"{s}.json" for s in a.session] if a.session
             else sorted(p for p in config.REPORTS_DIR.glob("*.json") if not p.name.endswith(".verified.json")))
    totals = {"verified": 0, "unsupported": 0, "interpretive": 0}
    for p in paths:
        res = verify_report(con, load_report(p), strict_text=a.strict_text)
        p.with_suffix(".verified.json").write_text(json.dumps(res, indent=2))
        s = res["summary"]
        for k in totals:
            totals[k] += s[k]
        print(f"  {res['session_id']}: {s['verified']} verified, {s['unsupported']} unsupported, "
              f"{s['interpretive']} interpretive (groundedness {s['groundedness']})")
        if a.show:
            for c in res["claims"]:
                mark = {"verified": "OK ", "unsupported": "BAD", "interpretive": "INT"}[c["status"]]
                print(f"     [{mark}] {c['text']}")
                for r in c["reasons"]:
                    print(f"           - {r}")
    print(f"  total: {totals}")


def cmd_eval_verifier(a):
    from triage.evaluation import eval_perturbation
    res = eval_perturbation(db.connect(a.db, read_only=True), seed=a.seed)
    out = config.WORK_DIR / "verifier_perturbation.json"
    out.write_text(json.dumps(res, indent=2))
    print(f"  {res['reports']} reports")
    for k, v in res["by_mutation"].items():
        print(f"  {k:<14} caught {v['caught']:>4}/{v['tried']:<4} ({v['detection_rate']:.0%})")
    print(f"  overall detection rate: {res['overall_detection_rate']}  (details + missed examples in {out})")


def cmd_export_claims(a):
    from triage.evaluation import export_claims
    n = export_claims(db.connect(a.db, read_only=True), Path(a.out))
    print(f"  wrote {n} claims to {a.out} -- fill in human_label (supported/unsupported/interpretive)")


def cmd_score_claims(a):
    from triage.evaluation import score_claims
    print(json.dumps(score_claims(Path(a.labelled)), indent=2))


def main():
    ap = argparse.ArgumentParser(description="Agentic insider-threat triage pipeline")
    ap.add_argument("--db", default=None, help=f"DuckDB path (default {config.DB_PATH})")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("sample-data", help="write a small synthetic CERT-format dataset")
    p.add_argument("--out", default="datasets/sample")
    p.add_argument("--users", type=int, default=30)
    p.add_argument("--days", type=int, default=120)
    p.add_argument("--seed", type=int, default=7)
    p.set_defaults(fn=cmd_sample_data)

    p = sub.add_parser("ingest", help="load CERT CSVs (+answers) into DuckDB")
    p.add_argument("--cert-dir", required=True)
    p.add_argument("--answers-dir")
    p.add_argument("--release", default="r4.2")
    p.add_argument("--no-content", action="store_true", help="drop content columns (saves lots of space)")
    p.add_argument("--lenient", action="store_true", help="skip malformed CSV rows instead of failing")
    p.set_defaults(fn=cmd_ingest)

    p = sub.add_parser("sessions", help="build sessions and assign events")
    p.add_argument("--cap-hours", type=int, default=config.SESSION_CAP_HOURS)
    p.set_defaults(fn=cmd_sessions)

    p = sub.add_parser("features", help="build per-session features + labels")
    p.set_defaults(fn=cmd_features)

    p = sub.add_parser("detect", help="train/score anomaly detectors, write alerts")
    p.add_argument("--train-frac", type=float, default=0.5)
    p.add_argument("--models", nargs="+", default=["iforest", "ocsvm", "autoencoder"])
    p.add_argument("--primary", default="iforest")
    p.add_argument("--top-k", type=int, default=200)
    p.add_argument("--train-benign-only", action="store_true")
    p.set_defaults(fn=cmd_detect)

    p = sub.add_parser("investigate", help="run the agent on alerts")
    p.add_argument("--session", nargs="+", help="session ids (default: top alerts)")
    p.add_argument("--top", type=int, default=10)
    p.add_argument("--backend", choices=["mock", "openai"], default="mock",
                   help="'openai' = any OpenAI-compatible endpoint (Ollama, LM Studio, OpenAI, Groq...)")
    p.add_argument("--model")
    p.add_argument("--base-url")
    p.add_argument("--max-steps", type=int, default=8)
    p.add_argument("--hallucinate", type=int, default=0, help="mock only: inject N wrong claims per report")
    p.set_defaults(fn=cmd_investigate)

    p = sub.add_parser("verify", help="verify saved reports")
    p.add_argument("--session", nargs="+")
    p.add_argument("--show", action="store_true", help="print every claim")
    p.add_argument("--strict-text", action="store_true", help="text-anchoring failures count as unsupported")
    p.set_defaults(fn=cmd_verify)

    p = sub.add_parser("eval-verifier", help="error-injection evaluation of the verifier")
    p.add_argument("--seed", type=int, default=0)
    p.set_defaults(fn=cmd_eval_verifier)

    p = sub.add_parser("export-claims", help="CSV of claims for manual labelling")
    p.add_argument("--out", default=str(config.WORK_DIR / "claims_to_label.csv"))
    p.set_defaults(fn=cmd_export_claims)

    p = sub.add_parser("score-claims", help="compare verifier with manual labels")
    p.add_argument("labelled")
    p.set_defaults(fn=cmd_score_claims)

    a = ap.parse_args()
    config.ensure_dirs()
    a.fn(a)


if __name__ == "__main__":
    main()
