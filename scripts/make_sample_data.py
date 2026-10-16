"""Generate a small synthetic dataset in CERT r4.2 format (+ answers archive layout).

Purpose: lets everyone run and test the whole pipeline in seconds before the real
CERT download is ready. It is NOT a substitute for CERT in any reported results.

Includes three planted insiders that loosely mirror the r4.2 scenarios:
  1. after-hours logon + USB + wikileaks uploads
  2. job-site browsing for weeks, then USB + mass file copies
  3. admin downloads a keylogger, copies it to USB, uses a supervisor's PC after hours
"""
from __future__ import annotations

import argparse
import csv
import random
import string
from datetime import datetime, timedelta
from pathlib import Path

DOMAIN = "dtaa.com"
NORMAL_SITES = ["google.com", "bing.com", "yahoo.com", "cnn.com", "bbc.co.uk", "espn.com",
                "weather.com", "amazon.com", "wikipedia.org", "github.com", "stackoverflow.com",
                "nytimes.com", "reddit.com", "microsoft.com", "dtaa.com/intranet"]
JOB_SITES = ["indeed.com", "monster.com", "careerbuilder.com", "simplyhired.com", "linkedin.com/jobs"]
FILE_EXT = [".doc", ".pdf", ".txt", ".jpg", ".xls"]
WORDS = ("report quarterly budget meeting project status update client schedule review "
         "design draft final notes summary team deadline invoice travel lunch").split()


def rid(rng: random.Random) -> str:
    a = string.ascii_uppercase + string.digits
    part = lambda n: "".join(rng.choice(a) for _ in range(n))  # noqa: E731
    return "{" + f"{part(4)}-{part(8)}-{part(8)}" + "}"


def fmt(t: datetime) -> str:
    return t.strftime("%m/%d/%Y %H:%M:%S")


def words(rng, n=6):
    return " ".join(rng.choice(WORDS) for _ in range(n))


class Gen:
    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.rows = {k: [] for k in ["logon", "device", "http", "email", "file"]}
        self.malicious: dict[str, list[list[str]]] = {}

    def add(self, src, t, user, pc, *fields, bad_for: str | None = None):
        row = [rid(self.rng), fmt(t), user, pc, *fields]
        self.rows[src].append(row)
        if bad_for:
            self.malicious.setdefault(bad_for, []).append([src] + row)
        return row

    def session(self, user, pc, start, end, profile, colleagues, bad_for=None, extra=None):
        r = self.rng
        self.add("logon", start, user, pc, "Logon", bad_for=bad_for)
        span = max((end - start).total_seconds(), 60)
        at = lambda: start + timedelta(seconds=r.uniform(30, span - 30))  # noqa: E731
        for _ in range(r.randint(*profile["http"])):
            site = r.choice(JOB_SITES) if r.random() < profile.get("job", 0) else r.choice(NORMAL_SITES)
            self.add("http", at(), user, pc, f"http://{site}/{r.choice(WORDS)}", words(r))
        for _ in range(r.randint(*profile["email"])):
            ext = r.random() < 0.1
            to = (f"{r.choice(WORDS)}{r.randint(1, 99)}@{r.choice(['gmail.com', 'yahoo.com', 'acme.org'])}"
                  if ext else f"{r.choice(colleagues)}@{DOMAIN}")
            self.add("email", at(), user, pc, to, "", "", f"{user}@{DOMAIN}",
                     str(r.randint(5000, 60000)), str(int(r.random() < 0.2)), words(r))
        if r.random() < profile["usb"]:
            t = at()
            self.add("device", t, user, pc, "Connect")
            for _ in range(r.randint(0, 3)):
                self.add("file", t + timedelta(minutes=r.uniform(1, 10)), user, pc,
                         f"{r.choice(WORDS)}{r.choice(FILE_EXT)}", words(r))
            self.add("device", t + timedelta(minutes=r.uniform(12, 40)), user, pc, "Disconnect")
        if extra:
            extra(self, user, pc, start, end)
        if not (r.random() < 0.02):  # occasional missing logoff, like real CERT
            self.add("logon", end, user, pc, "Logoff", bad_for=bad_for)


def build(out: Path, n_users: int = 30, n_days: int = 120, seed: int = 7) -> None:
    g = Gen(seed)
    r = g.rng
    users = [f"{''.join(r.choice(string.ascii_uppercase) for _ in range(3))}{r.randint(1000, 9999)}"
             for _ in range(n_users)]
    pcs = {u: f"PC-{r.randint(1000, 9999)}" for u in users}
    profiles = {}
    for i, u in enumerate(users):
        profiles[u] = {
            "http": (5, 25), "email": (0, 6),
            "usb": 0.35 if i % 6 == 0 else 0.02,        # a few legit heavy USB users
            "job": 0.05 if i % 10 == 3 else 0.0,         # some benign job browsing
            "late": 0.15 if i % 7 == 1 else 0.01,        # a few people who work late
        }
    s1, s2, s3, boss = users[1], users[2], users[3], users[4]
    profiles[s2]["job"] = 0.0
    start_day = datetime(2010, 1, 4)

    def leak_night(gen, user, pc, start, end):
        gen.add("device", start + timedelta(minutes=3), user, pc, "Connect", bad_for=user)
        for k in range(r.randint(3, 6)):
            gen.add("http", start + timedelta(minutes=5 + k * 4), user, pc,
                    f"http://wikileaks.org/upload/{r.choice(WORDS)}", words(r), bad_for=user)
        gen.add("device", end - timedelta(minutes=5), user, pc, "Disconnect", bad_for=user)

    def job_browsing(gen, user, pc, start, end):
        for _ in range(r.randint(2, 5)):
            gen.add("http", start + timedelta(minutes=r.uniform(10, 400)), user, pc,
                    f"http://{r.choice(JOB_SITES)}/{r.choice(['apply', 'search', 'resume'])}", words(r),
                    bad_for=user)

    def mass_copy(gen, user, pc, start, end):
        t = start + timedelta(hours=2)
        gen.add("device", t, user, pc, "Connect", bad_for=user)
        for k in range(r.randint(15, 30)):
            gen.add("file", t + timedelta(minutes=k), user, pc,
                    f"{r.choice(WORDS)}_{r.choice(WORDS)}{r.choice(FILE_EXT)}", words(r), bad_for=user)
        gen.add("device", t + timedelta(minutes=40), user, pc, "Disconnect", bad_for=user)

    def keylogger_download(gen, user, pc, start, end):
        t = start + timedelta(hours=1)
        gen.add("http", t, user, pc, "http://keylogger-pro.net/download/kl.exe", "download free keylogger",
                bad_for=user)
        gen.add("device", t + timedelta(minutes=5), user, pc, "Connect", bad_for=user)
        gen.add("file", t + timedelta(minutes=6), user, pc, "kl.exe", "binary", bad_for=user)
        gen.add("device", t + timedelta(minutes=8), user, pc, "Disconnect", bad_for=user)

    def keylogger_install(gen, user, pc, start, end):
        gen.add("device", start + timedelta(minutes=2), user, pc, "Connect", bad_for=user)
        gen.add("file", start + timedelta(minutes=3), user, pc, "kl.exe", "binary", bad_for=user)
        gen.add("device", start + timedelta(minutes=9), user, pc, "Disconnect", bad_for=user)

    for d in range(n_days):
        day = start_day + timedelta(days=d)
        weekend = day.weekday() >= 5
        for u in users:
            p = profiles[u]
            if weekend and r.random() > 0.03:
                continue
            if not weekend and r.random() < 0.05:
                continue  # leave / sick day
            st = day + timedelta(hours=r.gauss(8.4, 0.5))
            en = day + timedelta(hours=r.gauss(17.4, 0.6))
            if r.random() < p["late"]:
                en = day + timedelta(hours=r.uniform(19.5, 22.5))
            extra, bad = None, None
            if u == s2 and 60 <= d <= 100 and r.random() < 0.5:
                extra = job_browsing   # only the job-site events themselves are malicious
            if u == s2 and d in (102, 104, 106):
                extra = mass_copy
            if u == s3 and d == 85:
                extra = keylogger_download
            g.session(u, pcs[u], st, en, p, users, bad_for=bad, extra=extra)
        if d in (82, 89, 93):  # scenario 1: night sessions
            st = day + timedelta(hours=r.uniform(22, 23))
            g.session(s1, pcs[s1], st, st + timedelta(minutes=r.uniform(35, 60)),
                      {"http": (0, 1), "email": (0, 0), "usb": 0.0}, users, bad_for=s1, extra=leak_night)
        if d == 88:  # scenario 3: admin uses supervisor's PC after hours
            st = day + timedelta(hours=20.5)
            g.session(s3, pcs[boss], st, st + timedelta(minutes=15),
                      {"http": (0, 0), "email": (0, 0), "usb": 0.0}, users, bad_for=s3,
                      extra=keylogger_install)

    out = Path(out)
    cert, answers = out / "r4.2", out / "answers"
    cert.mkdir(parents=True, exist_ok=True)
    headers = {
        "logon": "id,date,user,pc,activity",
        "device": "id,date,user,pc,activity",
        "http": None,  # real r4.2 http.csv may lack a header; exercise that path
        "email": "id,date,user,pc,to,cc,bcc,from,size,attachments,content",
        "file": "id,date,user,pc,filename,content",
    }
    for src, rows in g.rows.items():
        rows.sort(key=lambda x: datetime.strptime(x[1], "%m/%d/%Y %H:%M:%S"))
        with open(cert / f"{src}.csv", "w", newline="") as fh:
            w = csv.writer(fh, lineterminator="\n")
            if headers[src]:
                fh.write(headers[src] + "\n")
            w.writerows(rows)

    scen = {s1: 1, s2: 2, s3: 3}
    answers.mkdir(parents=True, exist_ok=True)
    with open(answers / "insiders.csv", "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["dataset", "scenario", "details", "user", "start", "end"])
        for u, rows in g.malicious.items():
            s = scen[u]
            fname = f"r4.2-{s}-{u}.csv"
            times = sorted(datetime.strptime(x[2], "%m/%d/%Y %H:%M:%S") for x in rows)
            w.writerow(["4.2", s, fname, u, fmt(times[0]), fmt(times[-1])])
            d = answers / f"r4.2-{s}"
            d.mkdir(exist_ok=True)
            with open(d / fname, "w", newline="") as fh2:
                csv.writer(fh2, lineterminator="\n").writerows(sorted(rows, key=lambda x: datetime.strptime(x[2], "%m/%d/%Y %H:%M:%S")))
    total = sum(len(v) for v in g.rows.values())
    print(f"Wrote {total:,} events for {n_users} users x {n_days} days to {cert}")
    print(f"Planted insiders: s1={s1} s2={s2} s3={s3} ({sum(len(v) for v in g.malicious.values())} malicious events)")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="datasets/sample")
    ap.add_argument("--users", type=int, default=30)
    ap.add_argument("--days", type=int, default=120)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args()
    build(Path(a.out), a.users, a.days, a.seed)
