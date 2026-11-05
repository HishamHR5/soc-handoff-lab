"""A small local SIEM. It reads data/datasets/<name>/logs.jsonl.

Each log line has: id, source, src_ip, ts, raw (and labels, which the agents never see).
Phase II: a WazuhSIEM class with the SAME methods can call the Wazuh API.
The agents do not change, because they only use these methods.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any


class LocalSIEM:
    def __init__(self, dataset_dir: Path, max_results: int = 50):
        with open(dataset_dir / "logs.jsonl") as f:
            self.logs: list[dict[str, Any]] = [json.loads(line) for line in f if line.strip()]
        self.by_id = {rec["id"]: rec for rec in self.logs}
        self.by_ip: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for rec in self.logs:
            self.by_ip[rec["src_ip"]].append(rec)
        rep = dataset_dir / "ip_reputation.json"
        self.reputation: dict[str, Any] = json.loads(rep.read_text()) if rep.exists() else {}
        self.max_results = max_results

    def logs_for_alert(self, alert: dict[str, Any], limit: int | None = None) -> list[dict[str, Any]]:
        """The log lines of the alert: its log_ids, or (old datasets) all lines of its IP and source."""
        if alert.get("log_ids"):
            rows = [self.by_id[i] for i in alert["log_ids"] if i in self.by_id]
        else:
            rows = [rec for rec in self.by_ip[alert["src_ip"]] if rec["source"] == alert["source"]]
        return rows[:limit] if limit else rows

    def search(self, ip: str) -> list[dict[str, Any]]:
        """Log lines from one IP, from all sources (at most max_results)."""
        return self.by_ip.get(ip, [])[: self.max_results]

    def get_log(self, log_id: str) -> dict[str, Any] | None:
        return self.by_id.get(log_id)

    def ip_reputation(self, ip: str) -> dict[str, Any]:
        rep: dict[str, Any] = self.reputation.get(ip, {"score": None, "note": "unknown"})
        return rep
