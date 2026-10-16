"""The contract between the investigation agent and the verifier.

Every report is a list of atomic claims. A FACTUAL claim must:
  * cite one or more event ids (`citations`)
  * state, in `asserted`, the field values it relies on -- these are checked against EVERY
    cited event by the verifier (see ASSERTABLE_FIELDS)
  * set `count` if the text states a number of events; it must equal len(set(citations))
An INTERPRETIVE claim (judgement, motive, "unusual for this user") needs no asserted
fields, but any ids it cites must still exist and belong to the user.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

# Keys the agent may use in `asserted`. Append `_contains` to any string field for a
# case-insensitive substring match, e.g. {"url_contains": "wikileaks.org"}.
ASSERTABLE_FIELDS = {
    "source": "logon | device | http | email | file",
    "activity": "Logon, Logoff, Connect, Disconnect, Visit, Send, File (exact value from the event)",
    "user": "user id",
    "pc": "machine id",
    "date": "timestamp 'YYYY-MM-DD HH:MM[:SS]' or a date 'YYYY-MM-DD' (checked at the precision given)",
    "time": "time of day 'HH:MM[:SS]'",
    "url": "http events: full URL",
    "filename": "file events: file name",
    "to": "email events: one recipient address",
    "cc": "email events: one cc address",
    "bcc": "email events: one bcc address",
    "from": "email events: sender",
    "size": "email events: size in bytes (integer)",
    "attachments": "email events: number of attachments (integer)",
}


class Claim(BaseModel):
    text: str
    type: Literal["factual", "interpretive"]
    citations: list[str] = Field(default_factory=list)
    asserted: dict[str, Any] = Field(default_factory=dict)
    count: int | None = None


class Report(BaseModel):
    session_id: str
    verdict: Literal["malicious", "suspicious", "benign", "unclear"] = "unclear"
    summary: str = ""
    claims: list[Claim] = Field(default_factory=list)


def schema_prompt() -> str:
    fields = "\n".join(f"    - {k}: {v}" for k, v in ASSERTABLE_FIELDS.items())
    return f"""Report JSON format:
{{
  "verdict": "malicious" | "suspicious" | "benign" | "unclear",
  "summary": "2-4 sentence plain-English summary for an analyst",
  "claims": [
    {{"text": "...", "type": "factual" | "interpretive",
      "citations": ["<event id>", ...],
      "asserted": {{"<field>": "<value copied exactly from the cited events>"}},
      "count": <integer, only if the text states a number of events>}}
  ]
}}
Rules for claims:
  - One fact per claim. Factual claims MUST cite event ids you actually saw in tool output.
  - Every value in "asserted" must be true for EVERY cited event. Copy values exactly.
  - If the text says "N events", set "count": N and cite exactly those N events.
  - Opinions, motives, risk judgements and comparisons with the user's history are "interpretive".
  - Allowed "asserted" fields (add the suffix _contains to any text field for a substring match):
{fields}"""
