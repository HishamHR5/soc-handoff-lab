"""Loaders: convert log files to the internal record format.

Internal record (one dict per log line):
  id      "log-0001" (given later by assign_ids)
  source  "auth.log" | "access.log" | "apache_error.log"
  src_ip  the client IP of the line
  ts      ISO 8601 time, or None if the line has no time
  raw     the original line
  labels  list of ground-truth labels (AIT-LDS, synthetic), or [] (no label = normal)

Lines with no client IP are skipped: the pipeline groups lines by IP.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}"
SYSLOG_TS_RE = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}:\d{2}:\d{2})")
SSHD_IP_RE = re.compile(rf"(?:from|rhost=)\s*({IPV4})|\[({IPV4})\]")
ACCESS_IP_TS_RE = re.compile(rf"({IPV4}) \S+ \S+ \[([^\]]+)\]")
ERROR_RE = re.compile(rf"^\[(\w{{3}} \w{{3}} +\d+ [\d:]+ \d{{4}})\].*?\[client ({IPV4})\]")

Record = dict[str, Any]


def parse_syslog_ts(line: str, year: int) -> str | None:
    m = SYSLOG_TS_RE.match(line)
    if not m:
        return None
    dt = datetime.strptime(f"{year} {m.group(1)} {int(m.group(2))} {m.group(3)}", "%Y %b %d %H:%M:%S")
    return dt.isoformat()


def parse_access_ts(text: str) -> str | None:
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z").isoformat()
    except ValueError:
        return None


def parse_auth_line(line: str, year: int) -> Record | None:
    """One sshd line from auth.log / OpenSSH logs."""
    if "sshd" not in line:
        return None
    m = SSHD_IP_RE.search(line)
    if not m:
        return None
    return {"source": "auth.log", "src_ip": m.group(1) or m.group(2),
            "ts": parse_syslog_ts(line, year), "raw": line, "labels": []}


def parse_access_line(line: str) -> Record | None:
    """One line of an Apache access log (common or combined format)."""
    m = ACCESS_IP_TS_RE.search(line)
    if not m:
        return None
    return {"source": "access.log", "src_ip": m.group(1), "ts": parse_access_ts(m.group(2)),
            "raw": line, "labels": []}


def parse_apache_error_line(line: str) -> Record | None:
    """One line of an Apache error log with a [client <ip>] part (LogHub Apache)."""
    m = ERROR_RE.search(line)
    if not m:
        return None
    ts = datetime.strptime(" ".join(m.group(1).split()), "%a %b %d %H:%M:%S %Y").isoformat()
    return {"source": "apache_error.log", "src_ip": m.group(2), "ts": ts, "raw": line, "labels": []}


def read_lines(path: Path) -> list[str]:
    with open(path, encoding="utf-8", errors="replace") as f:
        return [line.rstrip("\n") for line in f]


def load_openssh(path: Path, year: int = 2026) -> list[Record]:
    """LogHub OpenSSH (for example OpenSSH_2k.log). The lines have no year: give one."""
    return [r for line in read_lines(path) if (r := parse_auth_line(line, year))]


def load_apache_error(path: Path) -> list[Record]:
    """LogHub Apache (Apache_2k.log). Note: LogHub Apache is an ERROR log, not an access log."""
    return [r for line in read_lines(path) if (r := parse_apache_error_line(line))]


def load_apache_access(path: Path) -> list[Record]:
    return [r for line in read_lines(path) if (r := parse_access_line(line))]


def load_ait_labels(path: Path) -> dict[int, list[str]]:
    """AIT-LDS v2 label file: one JSON object per line, {"line": N, "labels": [...], ...}.

    N is the 1-based line number in the log file with the same relative path under gather/.
    Lines without a label object are normal.
    """
    labels: dict[int, list[str]] = {}
    if not path.exists():
        return labels
    for line in read_lines(path):
        if line.strip():
            obj = json.loads(line)
            labels[int(obj["line"])] = list(obj.get("labels", []))
    return labels


def load_aitlds(root: Path, files: Iterable[dict[str, str]], year: int) -> list[Record]:
    """AIT-LDS v2 scenario folder (for example data/raw/aitlds/fox).

    files: [{"path": "gather/<host>/logs/auth.log", "kind": "auth"},
            {"path": "gather/<host>/logs/apache2/<name>-access.log", "kind": "apache_access"}]
    The label file is the same path with "gather/" replaced by "labels/".
    """
    records: list[Record] = []
    for item in files:
        rel = item["path"]
        if not rel.startswith("gather/"):
            raise ValueError(f"AIT-LDS file path must start with 'gather/': {rel}")
        labels = load_ait_labels(root / ("labels/" + rel[len("gather/"):]))
        for number, line in enumerate(read_lines(root / rel), start=1):
            if item["kind"] == "auth":
                rec = parse_auth_line(line, year)
            elif item["kind"] == "apache_access":
                rec = parse_access_line(line)
            else:
                raise ValueError(f"unknown AIT-LDS file kind {item['kind']!r} (use auth or apache_access)")
            if rec:
                rec["labels"] = labels.get(number, [])
                records.append(rec)
    return records


def assign_ids(records: list[Record]) -> list[Record]:
    """Sort by time (stable; lines with no time keep their order) and give ids log-0001, ..."""
    ordered = sorted(enumerate(records), key=lambda p: (p[1]["ts"] or "", p[0]))
    out = []
    for n, (_, rec) in enumerate(ordered, start=1):
        out.append({"id": f"log-{n:04d}", **{k: v for k, v in rec.items() if k != "id"}})
    return out
