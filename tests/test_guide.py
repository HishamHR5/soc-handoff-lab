"""Tests for the GUIDE loader (data/guide.py) with a small made-up file in the GUIDE format."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from soclab.data.build import build_dataset, load_base, make_attacked
from soclab.data.guide import ID_FIELDS, find_placeholders, load_guide, render_row, sample_incidents
from soclab.runner import load_alerts

HEADER = ["Id", "OrgId", "IncidentId", "AlertId", "Timestamp", "DetectorId", "AlertTitle", "Category",
          "MitreTechniques", "IncidentGrade", "ActionGrouped", "ActionGranular", "EntityType", "EvidenceRole",
          *ID_FIELDS, "ThreatFamily", "ResourceType", "Roles", "AntispamDirection", "SuspicionLevel",
          "LastVerdict", "Usage"]
PLACEHOLDER = 999  # the "no value" ID in this file


def _row(i: int, org: int, inc: int, grade: str, **extra: object) -> dict[str, object]:
    row: dict[str, object] = {c: "" for c in HEADER}
    row.update({"Id": i, "OrgId": org, "IncidentId": inc, "AlertId": 100 + inc, "DetectorId": 7,
                "AlertTitle": 42, "Timestamp": f"2024-06-0{1 + i % 9}T10:00:00.000Z", "Category": "InitialAccess",
                "MitreTechniques": "T1078;T1110", "IncidentGrade": grade, "EntityType": "User",
                "EvidenceRole": "Impacted", "Usage": "Public"})
    row.update({c: PLACEHOLDER for c in ID_FIELDS})
    row.update(extra)
    return row


@pytest.fixture
def guide_csv(tmp_path: Path) -> Path:
    rows, i = [], 0
    for grade_index, grade in enumerate(["TruePositive", "BenignPositive", "FalsePositive"]):
        for inc in range(4):  # 4 incidents per label, 2 rows each
            for _ in range(2):
                i += 1
                rows.append(_row(i, org=grade_index + 1, inc=inc, grade=grade))
    rows[0].update({"IpAddress": 1234, "ActionGrouped": "ContainAccount", "LastVerdict": "Malicious"})
    path = tmp_path / "GUIDE_Test.csv"
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER)
        writer.writeheader()
        writer.writerows(rows)
    return path


def test_placeholders_and_render(guide_csv):
    placeholders = find_placeholders(guide_csv)
    assert placeholders["IpAddress"] == PLACEHOLDER and placeholders["DeviceId"] == PLACEHOLDER
    line = render_row(_row(1, 1, 0, "TruePositive", IpAddress=1234, ActionGrouped="ContainAccount",
                           LastVerdict="Malicious"), placeholders)
    assert line.startswith("2024-06-02T10:00:00Z alert=100 title=#42 detector=#7 category=InitialAccess")
    assert "mitre_techniques=T1078,T1110" in line and "ip_address=#1234" in line
    assert "last_verdict=Malicious" in line
    assert str(PLACEHOLDER) not in line  # "no value" IDs are left out
    for label in ("TruePositive", "ContainAccount", "Public"):  # labels never reach the agents
        assert label not in line


def test_sample_is_balanced_and_repeatable(guide_csv):
    chosen = sample_incidents(guide_csv, per_grade=2, seed=7)
    assert sorted(chosen.values()) == ["BP", "BP", "FP", "FP", "TP", "TP"]
    assert sample_incidents(guide_csv, per_grade=2, seed=7) == chosen
    assert len(sample_incidents(guide_csv, per_grade=50, seed=7)) == 12  # not more than there are


def test_load_guide(guide_csv):
    logs, alerts = load_guide(guide_csv, per_grade=4, seed=1, max_rows=1)
    assert len(alerts) == 12 and len(logs) == 12  # max_rows=1 keeps one line per incident
    alert = alerts[0]
    assert alert["source"] == "guide" and alert["truth_source"] == "guide_analyst_label"
    assert alert["rule"].startswith("Microsoft XDR incident: 1 alert(s), 2 evidence row(s)")
    rec = next(r for r in logs if r["id"] == alert["log_ids"][0])
    assert rec["src_ip"] == alert["src_ip"] == alert["alert_id"].replace("G-", "guide-")
    with pytest.raises(FileNotFoundError, match="download_data.py guide"):
        load_guide(guide_csv.parent / "missing.csv")


def test_guide_dataset_is_clean_only(guide_csv, tmp_path):
    base = load_base({"source": "guide", "path": str(guide_csv), "n": 1}, seed=7)
    assert {a["truth"] for a in base.alerts} == {"TP", "BP", "FP"}
    _, attacked = make_attacked(base, "CONCEAL", "direct", 7)
    assert attacked == []  # GUIDE has no attacker-controlled field
    out = tmp_path / "ds"
    info = build_dataset({"source": "guide", "path": str(guide_csv), "n": 2}, "NONE", "direct", 7, out)
    assert info["n_alerts"] == 6 and len(load_alerts(out)) == 6
