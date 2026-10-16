"""Controlled error injection for evaluating the verifier.

Take claims the verifier marked 'verified', break exactly one thing, and check the verifier
now rejects them. Gives a per-error-type detection rate (recall on known-bad claims), and the
untouched claims give the false-rejection rate.
"""
from __future__ import annotations

import random
from datetime import datetime, timedelta

from ..agent.schema import Claim

MUTATIONS = ["fake_id", "swap_citation", "shift_time", "wrong_pc", "wrong_count", "wrong_url",
             "drop_citation"]


def mutate(con, claim: Claim, kind: str, rng: random.Random, session_user: str) -> Claim | None:
    """Return a broken copy of `claim`, or None if this mutation does not apply."""
    c = claim.model_copy(deep=True)
    if kind == "fake_id":
        i = rng.randrange(len(c.citations))
        c.citations[i] = "{FAKE-" + "".join(rng.choice("ABCDEFGH23456789") for _ in range(8)) + "-ZZZZZZZZ}"
        return c
    if kind == "swap_citation":
        # Replace one citation with a REAL event of the same user but a different source.
        # Only caught if the claim asserts something that the swapped event contradicts.
        src = c.asserted.get("source")
        row = con.execute(
            'SELECT id FROM events WHERE "user" = ? AND source <> ? ORDER BY hash(id || ?) LIMIT 1',
            [session_user, src or "__none__", str(rng.random())]).fetchone()
        if row is None:
            return None
        c.citations[rng.randrange(len(c.citations))] = row[0]
        return c
    if kind == "shift_time":
        if "date" not in c.asserted:
            return None
        try:
            t = datetime.fromisoformat(str(c.asserted["date"]))
        except ValueError:
            return None
        c.asserted["date"] = (t + timedelta(minutes=rng.choice([-120, -45, 45, 120]))).strftime("%Y-%m-%d %H:%M:%S")
        return c
    if kind == "wrong_pc":
        if "pc" not in c.asserted:
            return None
        c.asserted["pc"] = "PC-" + str(rng.randint(10000, 99999))
        return c
    if kind == "wrong_count":
        if c.count is None:
            return None
        c.count = c.count + rng.choice([1, 2, 5])
        return c
    if kind == "wrong_url":
        key = next((k for k in c.asserted if k.startswith("url")), None)
        if key is None:
            return None
        c.asserted[key] = rng.choice(["dropbox.com", "mega.nz", "pastebin.com", "google.com"])
        return c
    if kind == "drop_citation":
        if c.type != "factual":
            return None
        c.citations = []
        return c
    raise ValueError(kind)
