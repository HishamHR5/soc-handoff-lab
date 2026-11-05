"""Experiment runner: a matrix of model x topology x defense x goal x variant x repeats.

Each CELL (one model, topology, defense, goal, variant) writes one tracer file:
  runs/<experiment>/cells/<cell_id>.jsonl
A clean cell (goal NONE) is added for each model x topology x defense, for the clean
metrics and the verdict change rate.

Resume: a run is finished when its "result" event is in the cell file. On a new start,
the events of unfinished runs are removed and only the missing runs are done.
Parallel: cells run in threads (--workers). One cell is never split over threads.
Manifest: runs/<experiment>/manifest.json (config, git commit, seed, package versions,
dataset hashes, times, finished/failed cells).
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import platform
import subprocess
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from .config import DATA, ROOT, RUNS, deep_merge, load_dotenv, load_settings
from .llm import LLM, make_llm
from .payloads import GOALS, VARIANTS
from .runner import load_alerts, run_alert

PACKAGES = ["soclab", "langgraph", "openai", "anthropic", "httpx", "pydantic", "pandas", "numpy",
            "matplotlib", "jsonschema", "pyyaml"]


@dataclass(frozen=True)
class Cell:
    model_id: str
    topology: str
    defense: str
    goal: str
    variant: str

    @property
    def cell_id(self) -> str:
        return f"{self.model_id}__{self.topology}__{self.defense}__{self.goal}__{self.variant}"


def load_experiment(path: Path) -> dict[str, Any]:
    exp: dict[str, Any] = yaml.safe_load(Path(path).read_text())
    exp.setdefault("name", Path(path).stem)
    exp.setdefault("seed", 7)
    exp.setdefault("repeats", 1)
    exp.setdefault("workers", 1)
    exp.setdefault("dataset", {"source": "samples"})
    exp.setdefault("topologies", ["chain"])
    exp.setdefault("defenses", ["none"])
    exp.setdefault("goals", GOALS)
    exp.setdefault("variants", ["direct"])
    for goal in exp["goals"]:
        if goal not in GOALS:
            raise ValueError(f"unknown goal {goal!r}")
    for variant in exp["variants"]:
        if variant not in VARIANTS:
            raise ValueError(f"unknown variant {variant!r}")
    if not exp.get("models"):
        raise ValueError("the experiment needs at least one entry under 'models'")
    return exp


def expand(exp: dict[str, Any]) -> list[Cell]:
    cells = []
    for model in exp["models"]:
        for topology in exp["topologies"]:
            for defense in exp["defenses"]:
                cells.append(Cell(model["id"], topology, defense, "NONE", "none"))
                cells += [Cell(model["id"], topology, defense, goal, variant)
                          for goal in exp["goals"] for variant in exp["variants"]]
    return cells


def prepare_datasets(exp: dict[str, Any], root: Path) -> dict[tuple[str, str], Path]:
    """Build each (goal, variant) dataset once. An existing folder is reused (resume)."""
    from .data.build import build_dataset

    out = {}
    for goal, variant in {("NONE", "none")} | {(g, v) for g in exp["goals"] for v in exp["variants"]}:
        path = root / f"{goal}_{variant}"
        if not (path / "info.json").exists():
            build_dataset(exp["dataset"], goal, "direct" if goal == "NONE" else variant, int(exp["seed"]), path,
                          exp.get("field"))
        out[(goal, variant)] = path
    return out


def finished_runs(path: Path) -> set[str]:
    """Run ids with a result event. Events of unfinished runs are removed from the file."""
    if not path.exists():
        return set()
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    done = {e["run_id"] for e in events if e["kind"] == "result"}
    keep = [e for e in events if e["run_id"] in done]
    if len(keep) != len(events):
        path.write_text("".join(json.dumps(e) + "\n" for e in keep))
    return done


def cell_settings(exp: dict[str, Any], base: dict[str, Any], model: dict[str, Any], cell: Cell) -> dict[str, Any]:
    s = deep_merge(base, exp.get("settings"))
    s["llm"] = deep_merge(s["llm"], model.get("llm"))
    s["pipeline"]["topology"] = cell.topology
    s["defense"]["name"] = cell.defense
    return s


def run_cell(cell: Cell, exp: dict[str, Any], settings: dict[str, Any], llm: LLM, dataset: Path,
             out_dir: Path, judge_llm: Any = None, max_alerts: int | None = None) -> dict[str, int]:
    out_file = out_dir / "cells" / f"{cell.cell_id}.jsonl"
    done = finished_runs(out_file)
    alerts = load_alerts(dataset)[:max_alerts]
    new = 0
    for alert in alerts:
        for repeat in range(int(exp["repeats"])):
            run_id = f"{alert['alert_id']}-r{repeat}"
            if run_id in done:
                continue
            seed = int(exp["seed"]) + repeat
            info = {"experiment": exp["name"], "cell_id": cell.cell_id, "repeat": repeat, "dataset": dataset.name}
            run_alert(alert, dataset, llm.with_seed(seed), settings, out_file, run_id, run_info=info,
                      judge_llm=judge_llm, seed=seed)
            new += 1
    return {"runs_total": len(alerts) * int(exp["repeats"]), "runs_new": new, "runs_skipped": len(done)}


def git_commit() -> str:
    try:
        sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True)
        dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True)
        return sha.stdout.strip() + ("-dirty" if dirty.stdout.strip() else "")
    except (OSError, subprocess.CalledProcessError):
        return "unknown (not a git repository)"


def package_versions() -> dict[str, str]:
    out = {}
    for name in PACKAGES:
        try:
            out[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            out[name] = "not installed"
    return out


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run_experiment(path: Path, *, workers: int | None = None, out_root: Path = RUNS,
                   data_root: Path = DATA / "datasets", max_alerts: int | None = None,
                   log: Any = print) -> dict[str, Any]:
    load_dotenv()
    exp = load_experiment(path)
    out_dir = out_root / exp["name"]
    out_dir.mkdir(parents=True, exist_ok=True)
    base = load_settings()
    datasets = prepare_datasets(exp, data_root / exp["name"])
    models = {m["id"]: m for m in exp["models"]}
    llms = {mid: make_llm(deep_merge(base["llm"], m.get("llm"))) for mid, m in models.items()}
    judge_cfg = deep_merge(base["laundering"], (exp.get("settings") or {}).get("laundering")).get("judge")
    judge_llm = make_llm(judge_cfg) if judge_cfg else None
    cells = expand(exp)

    manifest: dict[str, Any] = {
        "experiment": exp["name"], "file": str(path), "config": exp, "seed": exp["seed"],
        "git_commit": git_commit(), "python": sys.version.split()[0], "platform": platform.platform(),
        "packages": package_versions(), "started": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "datasets": {f"{g}_{v}": {"logs_sha256": file_sha256(p / "logs.jsonl"),
                                  "alerts_sha256": file_sha256(p / "alerts.jsonl")}
                     for (g, v), p in sorted(datasets.items())},
        "cells": len(cells), "status": "running", "cell_results": {}, "failed_cells": {},
    }
    manifest_file = out_dir / "manifest.json"
    manifest_file.write_text(json.dumps(manifest, indent=2, default=str))

    def one(cell: Cell) -> None:
        try:
            s = cell_settings(exp, base, models[cell.model_id], cell)
            r = run_cell(cell, exp, s, llms[cell.model_id], datasets[(cell.goal, cell.variant)], out_dir,
                         judge_llm, max_alerts)
            manifest["cell_results"][cell.cell_id] = r
            log(f"done   {cell.cell_id}: {r['runs_new']} new, {r['runs_skipped']} skipped")
        except Exception as e:  # one failed cell must not stop the others; a new start resumes it
            manifest["failed_cells"][cell.cell_id] = f"{type(e).__name__}: {e}"
            log(f"FAILED {cell.cell_id}: {e}\n{traceback.format_exc(limit=3)}")

    with ThreadPoolExecutor(max_workers=workers or int(exp["workers"])) as pool:
        list(pool.map(one, cells))

    manifest["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
    manifest["status"] = "failed" if manifest["failed_cells"] else "complete"
    manifest_file.write_text(json.dumps(manifest, indent=2, default=str))
    return manifest
