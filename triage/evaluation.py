"""Verifier evaluation.

1) eval_perturbation: inject known errors into verified claims, measure detection per error type.
2) export_claims / score_claims: the manual-labelling loop.
   export_claims writes every claim + verifier status to a CSV with an empty `human_label`
   column. Team members fill in supported / unsupported / interpretive by reading the raw
   logs, then score_claims reports agreement, precision and recall of the verifier.
"""
from __future__ import annotations

import csv
import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from . import config
from .agent.investigate import load_report
from .verifier.perturb import MUTATIONS, mutate
from .verifier.verify import verify_report


def _reports(reports_dir: Path):
    for p in sorted(Path(reports_dir).glob("*.json")):
        if p.name.endswith(".verified.json"):
            continue
        yield p, load_report(p)


def eval_perturbation(con, reports_dir: Path = config.REPORTS_DIR, seed: int = 0) -> dict:
    rng = random.Random(seed)
    tried, caught = Counter(), Counter()
    misses: dict[str, list] = defaultdict(list)
    n_reports = 0
    for _, rep in _reports(reports_dir):
        n_reports += 1
        res = verify_report(con, rep)
        user = con.execute('SELECT "user" FROM sessions WHERE session_id = ?', [rep.session_id]).fetchone()[0]
        for cr, claim in zip(res["claims"], rep.claims):
            if cr["status"] != "verified":
                continue
            for kind in MUTATIONS:
                broken = mutate(con, claim, kind, rng, user)
                if broken is None:
                    continue
                single = rep.model_copy(update={"claims": [broken]})
                status = verify_report(con, single)["claims"][0]["status"]
                tried[kind] += 1
                if status == "unsupported":
                    caught[kind] += 1
                elif len(misses[kind]) < 5:
                    misses[kind].append({"session": rep.session_id, "claim": broken.model_dump()})
    out = {"reports": n_reports, "by_mutation": {}}
    for k in MUTATIONS:
        if tried[k]:
            out["by_mutation"][k] = {"tried": tried[k], "caught": caught[k],
                                     "detection_rate": round(caught[k] / tried[k], 3)}
    total_t, total_c = sum(tried.values()), sum(caught.values())
    out["overall_detection_rate"] = round(total_c / total_t, 3) if total_t else None
    out["example_misses"] = misses
    return out


def export_claims(con, out_csv: Path, reports_dir: Path = config.REPORTS_DIR) -> int:
    rows = []
    for _, rep in _reports(reports_dir):
        res = verify_report(con, rep)
        for cr, claim in zip(res["claims"], rep.claims):
            rows.append({
                "session_id": rep.session_id, "claim_index": cr["index"], "type": claim.type,
                "text": claim.text, "citations": ";".join(claim.citations),
                "asserted": json.dumps(claim.asserted), "count": claim.count,
                "verifier_status": cr["status"], "verifier_reasons": " | ".join(cr["reasons"]),
                "human_label": "", "labeller": "", "notes": "",
            })
    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(out_csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]) if rows else ["session_id"])
        w.writeheader()
        w.writerows(rows)
    return len(rows)


def score_claims(labelled_csv: Path) -> dict:
    """Treat 'unsupported' as the positive class (the verifier's job is to catch bad claims)."""
    tp = fp = fn = tn = 0
    agree = n = 0
    for row in csv.DictReader(open(labelled_csv, newline="")):
        human = row["human_label"].strip().lower()
        if not human:
            continue
        human = {"supported": "verified"}.get(human, human)
        ver = row["verifier_status"]
        n += 1
        agree += human == ver
        h_bad, v_bad = human == "unsupported", ver == "unsupported"
        tp += h_bad and v_bad
        fp += (not h_bad) and v_bad
        fn += h_bad and not v_bad
        tn += (not h_bad) and not v_bad
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    return {"labelled": n, "agreement": round(agree / n, 3) if n else None,
            "unsupported_precision": prec, "unsupported_recall": rec,
            "confusion": {"tp": tp, "fp": fp, "fn": fn, "tn": tn}}
