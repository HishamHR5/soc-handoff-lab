"""Build a dataset folder: clean or attacked copies of logs + alerts.

A dataset folder (data/datasets/<name>/) has:
  logs.jsonl          one record per line (id, source, src_ip, ts, raw, labels)
  alerts.jsonl        one alert per line (with goal, variant, marker, payload, ...)
  ip_reputation.json  fake threat-intel data
  info.json           how the folder was made (source, goal, variant, seed, field)

Sources (dataset spec, key "source"):
  samples         data/samples (4 hand-made alerts)
  synthetic       data/synthetic.py (n scenarios of each type)
  loghub_openssh  data/raw/loghub/OpenSSH_2k.log    (scripts/download_data.py)
  loghub_apache   data/raw/loghub/Apache_2k.log     (error log)
  aitlds          an AIT-LDS v2 scenario folder (manual download, see scripts/download_data.py)
  guide           Microsoft GUIDE incidents, n per label (manual download; clean runs only)
"""

from __future__ import annotations

import copy
import json
import random
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..config import DATA
from ..fields import ATTACKER_FIELDS
from ..payloads import (
    custom_template,
    default_field,
    inject,
    load_templates,
    new_marker,
    plain_text,
    render,
)
from . import synthetic
from .alerts import build_alerts
from .guide import load_guide
from .loaders import (
    Record,
    assign_ids,
    load_aitlds,
    load_apache_error,
    load_openssh,
    parse_access_line,
    parse_auth_line,
)

SAMPLE_IP_RE = re.compile(r"(?:from |^)(\d+\.\d+\.\d+\.\d+)")


@dataclass
class BaseData:
    logs: list[Record]
    alerts: list[dict[str, Any]]
    reputation: dict[str, Any]


def load_samples(sample_dir: Path) -> BaseData:
    """The Phase I sample files. Ids are kept in file order (auth.log first), as before."""
    logs: list[Record] = []
    for source in ("auth.log", "access.log"):
        for raw in (sample_dir / source).read_text().splitlines():
            if not raw:
                continue
            rec = parse_auth_line(raw, 2026) if source == "auth.log" else parse_access_line(raw)
            ip_match = SAMPLE_IP_RE.search(raw)
            rec = rec or {"source": source, "src_ip": ip_match.group(1) if ip_match else "", "ts": None,
                          "raw": raw, "labels": []}
            logs.append({"id": f"log-{len(logs) + 1:04d}", **rec})
    alerts = [json.loads(line) for line in (sample_dir / "alerts.jsonl").read_text().splitlines() if line]
    for a in alerts:
        a.setdefault("truth_source", "manual")
    reputation = json.loads((sample_dir / "ip_reputation.json").read_text())
    return BaseData(logs, alerts, reputation)


def load_base(spec: dict[str, Any], seed: int = 7) -> BaseData:
    source = spec.get("source", "samples")
    max_logs = int(spec.get("max_logs_per_alert", 40))
    max_alerts = spec.get("max_alerts")
    raw_dir = Path(spec.get("raw_dir", DATA / "raw"))
    if source == "samples":
        return load_samples(Path(spec.get("path", DATA / "samples")))
    if source == "synthetic":
        logs, rep = synthetic.generate(seed=seed, n=int(spec.get("n", 2)))
    elif source == "loghub_openssh":
        logs, rep = assign_ids(load_openssh(raw_dir / "loghub" / "OpenSSH_2k.log", int(spec.get("year", 2026)))), {}
    elif source == "loghub_apache":
        logs, rep = assign_ids(load_apache_error(raw_dir / "loghub" / "Apache_2k.log")), {}
    elif source == "aitlds":
        root = Path(spec["root"])
        logs, rep = assign_ids(load_aitlds(root, spec["files"], int(spec["year"]))), {}
    elif source == "guide":  # alerts come from GUIDE incidents, not from the rules
        path = Path(spec.get("path", raw_dir / "guide" / "GUIDE_Test.csv"))
        logs, alerts = load_guide(path, int(spec.get("n", 20)), seed, max_logs)
        return BaseData(logs, alerts, {})
    else:
        raise ValueError(f"unknown dataset source {source!r}")
    alerts = build_alerts(logs, max_logs=max_logs, max_alerts=max_alerts, seed=seed)
    return BaseData(logs, alerts, rep)


def alert_lines(alert: dict[str, Any], logs: list[Record]) -> list[Record]:
    if alert.get("log_ids"):
        wanted = set(alert["log_ids"])
        return [rec for rec in logs if rec["id"] in wanted]
    return [rec for rec in logs if rec["src_ip"] == alert["src_ip"] and rec["source"] == alert["source"]]


def _targets(lines: list[Record], field: str, n_parts: int) -> list[tuple[Record, str]]:
    """Where to write the payload parts: (record, field) pairs, latest lines first.

    1 part : the last line that has the field.
    2 parts: 2 different fields of the last line if possible (access.log: url_path + field),
             else the field in the last 2 lines.
    """
    usable = [rec for rec in lines if inject(rec["raw"], rec["source"], "x", field) is not None]
    if not usable:
        return []
    last = usable[-1]
    if n_parts == 1:
        return [(last, field)]
    other = next((f for f in ATTACKER_FIELDS[last["source"]]
                  if f != field and inject(last["raw"], last["source"], "x", f) is not None), None)
    if other:
        return [(last, other), (last, field)]
    return [(rec, field) for rec in usable[-2:]] if len(usable) >= 2 else []


def make_attacked(base: BaseData, goal: str, variant: str, seed: int, field: str | None = None,
                  custom_text: str | None = None) -> tuple[list[Record], list[dict[str, Any]]]:
    """Copy the logs and put one payload into the lines of each targeted alert.

    custom_text: the user's own payload instead of the template text (see custom_template).
    """
    logs = copy.deepcopy(base.logs)
    if goal == "NONE":
        return logs, [{**a, "goal": "NONE", "variant": "none", "marker": None} for a in base.alerts]
    template = load_templates()[goal]
    if custom_text is not None:
        template = custom_template(template, custom_text)
    rng = random.Random(f"{seed}-{goal}-{variant}")
    out = []
    for alert in base.alerts:
        if alert["truth"] not in template["target_truth"]:
            continue
        use_field = field or default_field(alert["source"])
        if use_field is None or use_field not in ATTACKER_FIELDS.get(alert["source"], []):
            continue
        marker = new_marker(rng)
        parts = render(template, variant, marker)
        targets = _targets(alert_lines(alert, logs), use_field, len(parts))
        if len(targets) != len(parts):  # too few lines in the alert: use all lines of this IP
            same_ip = [r for r in logs if r["src_ip"] == alert["src_ip"] and r["source"] == alert["source"]]
            targets = _targets(same_ip, use_field, len(parts))
        if len(targets) != len(parts):
            continue
        for (rec, f), part in zip(targets, parts, strict=True):
            rec["raw"] = inject(rec["raw"], rec["source"], part, f)
        out.append({**alert, "goal": goal, "variant": variant, "marker": marker,
                    "payload": " | ".join(parts), "payload_plain": plain_text(template, variant, marker),
                    "injected_logs": [rec["id"] for rec, _ in targets],
                    "injected_fields": [f for _, f in targets]})
    return logs, out


def write_dataset(out_dir: Path, logs: list[Record], alerts: list[dict[str, Any]],
                  reputation: dict[str, Any], info: dict[str, Any]) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    with open(out_dir / "logs.jsonl", "w") as f:
        f.writelines(json.dumps(rec) + "\n" for rec in logs)
    with open(out_dir / "alerts.jsonl", "w") as f:
        f.writelines(json.dumps(a) + "\n" for a in alerts)
    (out_dir / "ip_reputation.json").write_text(json.dumps(reputation, indent=2))
    (out_dir / "info.json").write_text(json.dumps(info, indent=2))


def build_dataset(spec: dict[str, Any], goal: str, variant: str, seed: int, out_dir: Path,
                  field: str | None = None, *, custom_text: str | None = None) -> dict[str, Any]:
    base = load_base(spec, seed)
    logs, alerts = make_attacked(base, goal, variant, seed, field, custom_text)
    info = {"spec": spec, "goal": goal, "variant": variant, "seed": seed, "field": field,
            "n_logs": len(logs), "n_alerts": len(alerts)}
    if custom_text is not None:
        info["custom_text"] = custom_text
    write_dataset(out_dir, logs, alerts, base.reputation, info)
    return info
