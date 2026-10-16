# Agentic Triage for Insider Threat Detection: starter repo

ICT3214 Group 16. This repo contains a working skeleton of the whole pipeline from the proposal:

```
CERT logs ─▶ DuckDB ─▶ sessions ─▶ features ─▶ anomaly detector ─▶ alerts
                                                                     │
                     analyst UI ◀── verifier (deterministic) ◀── LLM agent (cited JSON claims)
```

Every stage runs end to end today: on a small **synthetic CERT-format sample**, and on the real
dataset once you download it. Each stage is a simple version that its owner is expected to replace
with something better. The interfaces between stages are what keep the team in sync.

---

## 1. Setup

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pytest -q                                              # 8 tests, about 3 seconds
```

## 2. Run everything on the sample (2 minutes)

```bash
python cli.py sample-data                                   # writes datasets/sample/ (CERT r4.2 format + answers)
python cli.py ingest --cert-dir datasets/sample/r4.2 --answers-dir datasets/sample/answers
python cli.py sessions
python cli.py features
python cli.py detect --top-k 50
python cli.py investigate --top 10                          # mock agent (no LLM needed)
python cli.py verify --show
python cli.py investigate --top 5 --hallucinate 2           # mock agent that lies twice per report...
python cli.py verify --show                                 # ...and the verifier catches it
python cli.py eval-verifier                                 # error-injection evaluation
streamlit run app/demo.py                                   # the demo UI
```

The sample is only for development. **Never report results from it.**

## 3. Run on the real CERT data

1. Download the **CERT Insider Threat Test Dataset** from CMU KiltHub. We use **r4.2**, the version
   most papers use (1,000 users, 70 insiders, 3 scenarios). Also download the separate
   **answers** archive. Extract both:
   ```
   datasets/r4.2/      logon.csv device.csv http.csv email.csv file.csv ...
   datasets/answers/   insiders.csv r4.2-1/ r4.2-2/ r4.2-3/ ...
   ```
2. Load it. `http.csv` is about 14 GB, and `--no-content` drops the page and email text, which saves most of the space:
   ```bash
   python cli.py ingest --cert-dir datasets/r4.2 --answers-dir datasets/answers --release r4.2 --no-content
   python cli.py sessions && python cli.py features && python cli.py detect
   ```
   If a CSV row is malformed, re-run with `--lenient`, but check how many rows were dropped.
   The loader reads the header if one is present. Files without a header are assumed to use the r4.2 column layout.
3. Everything lives in `work/cert.duckdb`. You can open it in Python (`duckdb.connect("work/cert.duckdb")`)
   or in the DuckDB CLI to explore. Tables: `logon device http email file events sessions features
   scores alerts malicious_events insiders`.

---

## 4. Repo map and who owns what

| Path | What it does now | Owner's next steps |
|---|---|---|
| `triage/ingest.py` | CSV to DuckDB; one narrow `events` table; answers to `malicious_events` | Load LDAP and psychometric data if the detector wants role features |
| `triage/sessions.py` | Logon→Logoff sessions; every event gets a `session_id` | Check the edge cases (missing logoffs, overnight sessions, shared PCs); try day-level windows as an alternative |
| `triage/features.py` | ~24 features per session, including past-only per-user deviations (`dev_*`) | Add features; run an **ablation** with and without the keyword features (`n_http_leak/job/hack`), because they encode domain knowledge |
| `triage/detect.py` | Isolation Forest, One-Class SVM, and a placeholder MLP autoencoder; time split; ROC-AUC, PR-AUC, P@k, insiders caught@k | Replace `autoencoder` with the real PyTorch autoencoder or a Transformer over event sequences. It only has to return one score per session. Tune the alert budget `top_k` |
| `triage/agent/` | `schema.py` (the claim contract), `tools.py` (4 read-only DB tools), `investigate.py` (JSON tool-calling loop + mock), `llm.py` (any OpenAI-compatible endpoint) | Prompt engineering; model choice; measure cost and latency per report; keep claims atomic |
| `triage/verifier/` | `verify.py` (deterministic checks), `perturb.py` (error injection) | Extend the checks (see section 6); the manual-labelling study |
| `triage/evaluation.py` | Perturbation eval; export, label and score claims against human labels | Run on **LLM** reports, not mock ones |
| `app/demo.py` | Streamlit: alert list, run agent, claims with green/red badges and the cited raw rows | Polish for the showcase; build a pilot mode that hides scores and records answers |

## 5. The claim contract (read this before touching the agent or the verifier)

The LLM never writes free prose for the verifier to parse. It returns JSON claims:

```json
{"text": "CRD6991 visited wikileaks.org 3 times during the session.",
 "type": "factual",
 "citations": ["{A1B2-...}", "{C3D4-...}", "{E5F6-...}"],
 "asserted": {"source": "http", "url_contains": "wikileaks.org"},
 "count": 3}
```

* A **factual** claim is verified only if all of these hold: every cited id exists, belongs to the session's user,
  every `asserted` field matches **every** cited event, and `count` equals the number of distinct citations.
  A factual claim that asserts nothing checkable is marked unsupported.
* An **interpretive** claim covers judgements, motives and "unusual for this user". It is shown as interpretation,
  and any id it cites must still exist.
* The fields the agent may assert are listed in `triage/agent/schema.py` (`ASSERTABLE_FIELDS`). Adding the
  `_contains` suffix to a text field gives a substring match. Dates are checked at the precision given.

## 6. Using a real LLM

The simplest free option is Ollama on your own machine:
```bash
ollama pull qwen2.5:14b            # or llama3.1:8b on a smaller GPU
python cli.py investigate --backend openai --base-url http://localhost:11434/v1 --model qwen2.5:14b --top 5
python cli.py verify --show
```
Any OpenAI-compatible API works the same way. Set `TRIAGE_LLM_BASE_URL`, `TRIAGE_LLM_MODEL` and
`TRIAGE_LLM_API_KEY`, and the Streamlit "Run LLM agent" button uses them too.
Each report is saved in `work/reports/<session>.json` together with the agent's tool-call trace.

**Known verifier gaps to discuss in the report and improve if you have time:**
- *Text vs. structure:* the verifier checks the `asserted` fields, not the prose. If the prose says
  something different, the verifier only gives a warning ("text anchoring"). `verify --strict-text` turns
  the warning into a failure. Measure how often this happens with real LLM output.
- *Aggregate claims* ("more USB activity than usual") are currently interpretive. Making them checkable
  against `get_user_baseline` numbers would be a nice extension.
- *Omissions:* a report can be fully verified and still leave out the most important event.
  One way to measure this: what fraction of the session's malicious events (from the answers file) the report cites.

## 7. Evaluation plan (proposal section 3.3)

| Level | Command / artifact | Metrics |
|---|---|---|
| Detector vs baselines | `detect` → `work/detector_metrics.json` | ROC-AUC, PR-AUC, precision/recall@k, insiders caught@k. Use the time split, and run several seeds |
| Verifier accuracy | `export-claims` → label `human_label` (two labellers per claim, and report their agreement) → `score-claims` | Agreement, and precision/recall for "unsupported" |
| Verifier robustness | `eval-verifier` | Detection rate for each injected error type. On mock reports this is a sanity check only. Run it on LLM reports |
| Human pilot | Demo app in pilot mode | Accuracy, time per case, confidence (Likert). Within-subjects and counterbalanced: alert only vs alert + verified report |

Check with the course team whether the human pilot needs ethics approval or a consent form before you recruit anyone.

## 8. Suggested 7-week timeline

| Week | Milestone |
|---|---|
| 1 | Everyone runs the sample pipeline. CERT r4.2 downloaded and ingested. Interfaces frozen |
| 2–3 | Detector baselines on real data; agent working with a real LLM; verifier extended |
| 4 | First integrated run: top 50 alerts, then reports, then verification. Start labelling claims |
| 5 | Detector improvements and ablations; pilot materials; pilot mode in the demo |
| 6 | Human pilot; final evaluation runs |
| 7 | Report, demo video, showcase polish |
