"""Loader for Microsoft GUIDE (Kaggle: Microsoft/microsoft-security-incident-prediction).

GUIDE is a TABLE of anonymized evidence rows, not raw log text. One incident (OrgId,
IncidentId) has one or more rows; each row is one piece of evidence of one alert. Names,
IPs, URLs, files and alert titles are integer IDs. The readable fields are the category,
the MITRE techniques, the entity type and role, and a few verdict fields.

This loader makes one alert per incident and turns each evidence row into one text line
(a "log line" for the agents), for example:

  2024-06-04T22:56:27Z alert=87199 title=#563 detector=#524 category=LateralMovement
  mitre=T1021,T1047 entity=User role=Impacted account_name=#863 last_verdict=Suspicious

Rules:
  * Labels never reach the agents: IncidentGrade is the ground truth, and ActionGrouped /
    ActionGranular (the remediation that analysts chose AFTER triage) are left out.
  * Placeholder IDs ("no value") are left out. A placeholder is the most frequent value of
    an ID column when it covers more than half of the first rows of the file.
  * Sampling: `per_grade` incidents for each label (TP, BP, FP), chosen with a fixed seed.
  * GUIDE has no attacker-controlled text field, so it is used for CLEAN runs only.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any

import pandas as pd

from .loaders import Record

GRADE_TO_TRUTH = {"TruePositive": "TP", "BenignPositive": "BP", "FalsePositive": "FP"}
KEY = ["OrgId", "IncidentId"]
LEFT_OUT = {"IncidentGrade", "ActionGrouped", "ActionGranular", "Usage", "Id"}  # labels and bookkeeping
TEXT_FIELDS = ["Category", "MitreTechniques", "EntityType", "EvidenceRole", "ThreatFamily", "ResourceType",
               "Roles", "AntispamDirection", "SuspicionLevel", "LastVerdict"]
ID_FIELDS = ["DeviceId", "Sha256", "IpAddress", "Url", "AccountSid", "AccountUpn", "AccountObjectId",
             "AccountName", "DeviceName", "NetworkMessageId", "EmailClusterId", "RegistryKey",
             "RegistryValueName", "RegistryValueData", "ApplicationId", "ApplicationName",
             "OAuthApplicationId", "FileName", "FolderPath", "ResourceIdName", "OSFamily", "OSVersion",
             "CountryCode", "State", "City"]
FIRST_ROWS = 500_000  # rows used to find the placeholder IDs
CHUNK = 500_000


def _snake(name: str) -> str:
    return "".join(f"_{c.lower()}" if c.isupper() and i else c.lower() for i, c in enumerate(name))


def find_placeholders(path: Path, nrows: int = FIRST_ROWS) -> dict[str, Any]:
    """{column: value} for ID columns where one value covers more than half of the first rows."""
    head = pd.read_csv(path, nrows=nrows, usecols=lambda c: c in ID_FIELDS, low_memory=False)
    out = {}
    for col in head.columns:
        counts = head[col].value_counts(dropna=True)
        if len(counts) and counts.iloc[0] > len(head) / 2:
            out[col] = counts.index[0]
    return out


def sample_incidents(path: Path, per_grade: int, seed: int) -> dict[tuple[int, int], str]:
    """{(org, incident): truth} with `per_grade` incidents per label, chosen with `seed`."""
    grades = pd.read_csv(path, usecols=[*KEY, "IncidentGrade"], low_memory=False).dropna()
    grades = grades.drop_duplicates(KEY)
    rng = random.Random(seed)
    chosen: dict[tuple[int, int], str] = {}
    for grade, truth in GRADE_TO_TRUTH.items():
        keys = sorted(map(tuple, grades.loc[grades.IncidentGrade == grade, KEY].to_numpy().tolist()))
        for org, inc in rng.sample(keys, min(per_grade, len(keys))):
            chosen[(int(org), int(inc))] = truth
    return chosen


def render_row(row: dict[str, Any], placeholders: dict[str, Any]) -> str:
    """One evidence row as one readable line (no labels, no placeholder IDs)."""
    ts = str(row.get("Timestamp", "")).replace(".000Z", "Z")
    parts = [ts, f"alert={row['AlertId']}", f"title=#{row['AlertTitle']}", f"detector=#{row['DetectorId']}"]
    for col in TEXT_FIELDS:
        value = row.get(col)
        if pd.isna(value) or str(value).startswith("DomainPII"):
            continue
        text = str(value).replace(";", ",") if col == "MitreTechniques" else str(value)
        parts.append(f"{_snake(col)}={text}")
    for col in ID_FIELDS:
        value = row.get(col)
        if value is None or pd.isna(value) or (col in placeholders and value == placeholders[col]):
            continue
        parts.append(f"{_snake(col)}=#{int(value)}")
    return " ".join(parts)


def load_guide(path: Path, per_grade: int = 20, seed: int = 7,
               max_rows: int = 40) -> tuple[list[Record], list[dict[str, Any]]]:
    """(log records, alerts) for a sample of GUIDE incidents; at most `max_rows` rows each."""
    if not path.exists():
        raise FileNotFoundError(f"{path} not found. See: python scripts/download_data.py guide")
    chosen = sample_incidents(path, per_grade, seed)
    placeholders = find_placeholders(path)
    parts = []
    for chunk in pd.read_csv(path, chunksize=CHUNK, low_memory=False):
        keys = list(zip(chunk.OrgId, chunk.IncidentId, strict=True))
        mask = [k in chosen for k in keys]
        if any(mask):
            parts.append(chunk[mask])
    rows = pd.concat(parts).sort_values([*KEY, "Timestamp", "Id"])

    logs: list[Record] = []
    alerts: list[dict[str, Any]] = []
    for (org, inc), group in rows.groupby(KEY, sort=True):
        key = (int(org), int(inc))
        source_key = f"guide-{key[0]}-{key[1]}"  # stands in for the source IP: one key per incident
        ids = []
        for row in group.head(max_rows).to_dict("records"):
            log_id = f"log-{len(logs) + 1:05d}"
            ids.append(log_id)
            logs.append({"id": log_id, "source": "guide", "src_ip": source_key, "ts": row["Timestamp"],
                         "raw": render_row(row, placeholders), "labels": []})
        categories = ", ".join(sorted(set(group.Category.dropna().astype(str))))
        alerts.append({"alert_id": f"G-{key[0]}-{key[1]}",
                       "rule": f"Microsoft XDR incident: {group.AlertId.nunique()} alert(s), {len(group)} evidence "
                               f"row(s); categories: {categories}",
                       "src_ip": source_key, "source": "guide", "truth": chosen[key],
                       "truth_source": "guide_analyst_label", "log_ids": ids})
    return logs, alerts
