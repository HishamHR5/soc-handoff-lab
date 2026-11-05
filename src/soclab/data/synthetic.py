"""Synthetic logs for tests and quick experiments. No download needed. Same seed = same logs.

Scenarios (n of each):
  ssh_bruteforce   TP  external IP, 6-10 invalid users in a few seconds     label "attack"
  ssh_typo         BP  internal user mistypes the name once, then logs in    label "benign_suspicious"
  web_scan         TP  external scanner, 404s on admin paths                 label "attack"
  internal_scanner BP  the IT vulnerability scanner, 404s on admin paths     label "benign_suspicious"
  health_probe     FP  Kubernetes probe, many /health requests                (no label)
  normal traffic       internal users browse and log in (no alert)            (no label)
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta
from typing import Any

from .loaders import Record, assign_ids

START = datetime(2026, 10, 12, 4, 0, 0)
USERNAMES = ["admin", "test", "oracle", "ubuntu", "root", "pi", "guest", "postgres", "ftpuser", "git"]
STAFF = ["alice", "bob", "carol", "dave", "erin"]
SCAN_PATHS = ["/wp-login.php", "/.env", "/phpmyadmin/", "/admin/config.php", "/.git/config",
              "/server-status", "/cgi-bin/test.cgi", "/backup.zip", "/xmlrpc.php", "/admin/"]
PAGES = ["/", "/index.html", "/news", "/about", "/static/app.js", "/static/style.css"]


def _syslog(ts: datetime, pid: int, msg: str) -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} gateway sshd[{pid}]: {msg}"  # syslog: "Oct  2 04:13:20"


def _access(ip: str, ts: datetime, path: str, status: int, size: int, ua: str, referer: str = "-") -> str:
    stamp = ts.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{stamp}] "GET {path} HTTP/1.1" {status} {size} "{referer}" "{ua}"'


def generate(seed: int = 7, n: int = 2) -> tuple[list[Record], dict[str, dict[str, Any]]]:
    """Return (log records with ids, IP reputation)."""
    rng = random.Random(seed)
    recs: list[Record] = []
    rep: dict[str, dict[str, Any]] = {}

    def add(source: str, ip: str, ts: datetime, raw: str, labels: list[str]) -> None:
        recs.append({"source": source, "src_ip": ip, "ts": ts.isoformat(), "raw": raw, "labels": labels})

    for i in range(n):
        base = START + timedelta(hours=i * 3)

        ip = f"198.51.100.{10 + i}"  # ssh_bruteforce (TP)
        rep[ip] = {"score": rng.randint(60, 95), "note": f"listed on {rng.randint(2, 6)} SSH abuse blocklists"}
        t = base + timedelta(minutes=rng.randint(0, 50))
        for k in range(rng.randint(6, 10)):
            user = rng.choice(USERNAMES)
            add("auth.log", ip, t, _syslog(t, 14000 + k, f"Invalid user {user} from {ip} port {40000 + 2 * k}"),
                ["attack", "bruteforce"])
            t += timedelta(seconds=1)

        ip = f"10.0.1.{20 + i}"  # ssh_typo (BP)
        user = STAFF[i % len(STAFF)]
        rep[ip] = {"score": 0, "note": f"workstation of {user}"}
        t = base + timedelta(minutes=rng.randint(55, 70))
        add("auth.log", ip, t, _syslog(t, 15000 + i, f"Invalid user {user[:-1]} from {ip} port 51100"),
            ["benign_suspicious"])
        t += timedelta(seconds=12)
        add("auth.log", ip, t, _syslog(t, 15001 + i, f"Accepted password for {user} from {ip} port 51102 ssh2"),
            ["benign_suspicious"])

        ip = f"203.0.113.{40 + i}"  # web_scan (TP)
        rep[ip] = {"score": rng.randint(70, 95), "note": f"listed on {rng.randint(2, 5)} scanner blocklists"}
        t = base + timedelta(minutes=rng.randint(75, 90))
        for path in rng.sample(SCAN_PATHS, rng.randint(6, 9)):
            add("access.log", ip, t, _access(ip, t, path, 404, 196, "Mozilla/5.0 (compatible; scanner)"), ["attack"])
            t += timedelta(seconds=1)

        ip = f"10.0.9.{5 + i}"  # internal_scanner (BP)
        rep[ip] = {"score": 0, "note": "IT vulnerability scanner (asset inventory)"}
        t = base + timedelta(minutes=rng.randint(95, 110))
        for path in rng.sample(SCAN_PATHS, 6):
            add("access.log", ip, t, _access(ip, t, path, 404, 196, "Nessus/10.7"), ["benign_suspicious"])
            t += timedelta(seconds=2)

        ip = f"10.0.2.{30 + i}"  # health_probe (FP)
        rep[ip] = {"score": 0, "note": "Kubernetes node"}
        t = base + timedelta(minutes=rng.randint(120, 140))
        for _ in range(25):
            add("access.log", ip, t, _access(ip, t, "/health", 200, 2, "kube-probe/1.29"), [])
            t += timedelta(seconds=5)

        for k in range(3):  # normal traffic (no alert)
            ip = f"10.0.3.{40 + 3 * i + k}"
            user = STAFF[(i + k) % len(STAFF)]
            rep[ip] = {"score": 0, "note": f"workstation of {user}"}
            t = base + timedelta(minutes=rng.randint(0, 170))
            add("auth.log", ip, t, _syslog(t, 16000 + k, f"Accepted publickey for {user} from {ip} port 52000 ssh2"), [])
            for page in rng.sample(PAGES, 3):
                t += timedelta(seconds=rng.randint(5, 60))
                add("access.log", ip, t, _access(ip, t, page, 200, rng.randint(500, 9000),
                                                 "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0"), [])
    return assign_ids(recs), rep
