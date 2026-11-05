"""Alert builder: simple SIEM rules over log records, with a ground-truth label.

Rules (one alert per IP per rule, from the first window where the rule fires):
  ssh_bruteforce     auth.log          >= 5 failed/invalid logins in 60 s
  ssh_invalid_user   auth.log          an invalid user, but fewer than 5 (and no brute force alert)
  web_scan           access.log        >= 5 responses 4xx in 60 s
  high_request_rate  access.log        >= 20 requests in 300 s
  apache_error_scan  apache_error.log  >= 5 "not found / forbidden" errors in 60 s

Ground truth from the record labels (truth_source "labels"):
  any line labelled as an attack            -> TP
  else any line labelled benign_suspicious  -> BP   (synthetic data only)
  else                                      -> FP
If the dataset has no labels at all (LogHub), truth is "TP" with truth_source "heuristic":
the rules fire on clear attack patterns, but nobody checked them. Report these alerts apart.
"""

from __future__ import annotations

import random
import re
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .loaders import Record

FAILED_SSH = re.compile(r"Invalid user|Failed password|authentication failure", re.I)
INVALID_USER = re.compile(r"Invalid user", re.I)
ACCESS_STATUS = re.compile(r'" (\d{3}) ')
ERROR_NOT_FOUND = re.compile(r"File does not exist|Directory index forbidden|client denied|script not found")
BENIGN_LABELS = {"benign_suspicious"}


@dataclass(frozen=True)
class Rule:
    name: str
    title: str
    source: str
    matches: Any  # Callable[[str], bool]
    min_count: int
    window_s: int


RULES = [
    Rule("ssh_bruteforce", "SSH brute force: 5+ failed logins in 60 s", "auth.log",
         lambda raw: bool(FAILED_SSH.search(raw)), 5, 60),
    Rule("ssh_invalid_user", "SSH invalid user", "auth.log",
         lambda raw: bool(INVALID_USER.search(raw)), 1, 60),
    Rule("web_scan", "Web scan: 5+ client errors (4xx) in 60 s", "access.log",
         lambda raw: bool((m := ACCESS_STATUS.search(raw)) and m.group(1).startswith("4")), 5, 60),
    Rule("high_request_rate", "High request rate: 20+ requests in 5 min", "access.log",
         lambda raw: True, 20, 300),
    Rule("apache_error_scan", "Web scan: 5+ not-found/forbidden errors in 60 s", "apache_error.log",
         lambda raw: bool(ERROR_NOT_FOUND.search(raw)), 5, 60),
]


def _seconds(rec: Record, index: int) -> float:
    return datetime.fromisoformat(rec["ts"]).timestamp() if rec.get("ts") else float(index)


def truth_for(lines: list[Record], dataset_has_labels: bool) -> tuple[str, str]:
    if not dataset_has_labels:
        return "TP", "heuristic"
    labels = {label for rec in lines for label in rec.get("labels", [])}
    if labels - BENIGN_LABELS:
        return "TP", "labels"
    if labels & BENIGN_LABELS:
        return "BP", "labels"
    return "FP", "labels"


def _first_window(rule: Rule, lines: list[Record]) -> list[Record] | None:
    hits = [(i, r) for i, r in enumerate(lines) if rule.matches(r["raw"])]
    times = [_seconds(r, i) for i, r in hits]
    for start in range(len(hits)):
        end = start
        while end + 1 < len(hits) and times[end + 1] - times[start] <= rule.window_s:
            end += 1
        if end - start + 1 >= rule.min_count:
            return [r for _, r in hits[start:end + 1]]
    return None


def build_alerts(logs: list[Record], *, max_logs: int = 40, max_alerts: int | None = None,
                 seed: int = 7, start_id: int = 1001) -> list[dict[str, Any]]:
    """Run the rules over the records and return alerts (sorted by time)."""
    has_labels = any(rec.get("labels") for rec in logs)
    groups: dict[tuple[str, str], list[Record]] = defaultdict(list)
    for rec in logs:
        groups[(rec["source"], rec["src_ip"])].append(rec)

    found = []
    for (source, ip), lines in sorted(groups.items()):
        fired: set[str] = set()
        for rule in RULES:
            if rule.source != source:
                continue
            if rule.name == "ssh_invalid_user" and "ssh_bruteforce" in fired:
                continue
            window = _first_window(rule, lines)
            if not window:
                continue
            fired.add(rule.name)
            truth, truth_source = truth_for(window, has_labels)
            found.append({
                "rule": rule.title, "rule_id": rule.name, "src_ip": ip, "source": source,
                "truth": truth, "truth_source": truth_source,
                "ts_first": window[0].get("ts"), "ts_last": window[-1].get("ts"),
                "log_ids": [r["id"] for r in window][:max_logs],
            })
    if max_alerts is not None and len(found) > max_alerts:
        found = _balanced_sample(found, max_alerts, seed)
    found.sort(key=lambda a: (a["ts_first"] or "", a["src_ip"], a["rule_id"]))
    return [{"alert_id": f"A-{start_id + n}", **a} for n, a in enumerate(found)]


def _balanced_sample(alerts: list[dict[str, Any]], k: int, seed: int) -> list[dict[str, Any]]:
    """Take k alerts, as equal as possible over the truth classes (seeded)."""
    rng = random.Random(seed)
    by_truth: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        by_truth[a["truth"]].append(a)
    for items in by_truth.values():
        rng.shuffle(items)
    out: list[dict[str, Any]] = []
    while len(out) < k:
        for truth in sorted(by_truth):
            if by_truth[truth] and len(out) < k:
                out.append(by_truth[truth].pop())
    return out
