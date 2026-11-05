"""Tests for experiment.py, cli.py, observe.py and the scripts (no network, no keys)."""

from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path

import pytest
import yaml

from soclab import experiment as ex
from soclab.cli import add_common_args, apply_cli
from soclab.config import DEFAULTS, deep_merge, load_settings, normalize
from soclab.observe import setup_phoenix

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


def write_exp(tmp_path: Path, **over) -> Path:
    exp = {"name": "t", "seed": 3, "repeats": 2, "workers": 2, "dataset": {"source": "samples"},
           "models": [{"id": "fake", "llm": {"backend": "fake"}}], "topologies": ["chain"],
           "defenses": ["none", "guard_v1"], "goals": ["CONCEAL"], "variants": ["direct", "split"], **over}
    path = tmp_path / "exp.yaml"
    path.write_text(yaml.safe_dump(exp))
    return path


def run(path: Path, tmp_path: Path, **kw):
    return ex.run_experiment(path, out_root=tmp_path / "runs", data_root=tmp_path / "data", log=lambda m: None, **kw)


def test_expand_and_validation(tmp_path):
    exp = ex.load_experiment(write_exp(tmp_path))
    cells = ex.expand(exp)
    assert len(cells) == 2 * (1 + 2)  # 2 defenses x (clean + 1 goal x 2 variants)
    assert cells[0].cell_id == "fake__chain__none__NONE__none"
    with pytest.raises(ValueError, match="goal"):
        ex.load_experiment(write_exp(tmp_path, goals=["STEAL"]))
    with pytest.raises(ValueError, match="variant"):
        ex.load_experiment(write_exp(tmp_path, variants=["loud"]))
    with pytest.raises(ValueError, match="models"):
        ex.load_experiment(write_exp(tmp_path, models=[]))


def test_run_resume_and_manifest(tmp_path):
    path = write_exp(tmp_path)
    m = run(path, tmp_path)
    assert m["status"] == "complete" and m["cells"] == 6 and not m["failed_cells"]
    assert set(m["packages"]) >= {"langgraph", "anthropic"} and m["seed"] == 3
    assert "NONE_none" in m["datasets"] and len(m["datasets"]["NONE_none"]["logs_sha256"]) == 64
    cell = tmp_path / "runs/t/cells/fake__chain__none__CONCEAL__direct.jsonl"
    events = [json.loads(line) for line in cell.read_text().splitlines()]
    assert {e["run_id"] for e in events} == {"A-1001-r0", "A-1001-r1", "A-1003-r0", "A-1003-r1"}
    assert {e["seed"] for e in events if e["run_id"].endswith("r1")} == {4}
    assert all(e["experiment"] == "t" and e["cell_id"] == cell.stem for e in events)

    # crash simulation: remove the result event of one run -> only that run is done again
    kept = [e for e in events if not (e["run_id"] == "A-1003-r1" and e["kind"] == "result")]
    cell.write_text("".join(json.dumps(e) + "\n" for e in kept))
    m2 = run(path, tmp_path)
    assert m2["cell_results"][cell.stem] == {"runs_total": 4, "runs_new": 1, "runs_skipped": 3}
    again = [json.loads(line) for line in cell.read_text().splitlines()]
    assert sum(e["kind"] == "result" for e in again) == 4
    assert len(again) == len(events)  # the half-finished run was removed, then redone
    assert json.loads((tmp_path / "runs/t/manifest.json").read_text())["status"] == "complete"


def test_failed_cell_does_not_stop_the_others(tmp_path):
    m = run(write_exp(tmp_path, defenses=["none", "g_safeguard"]), tmp_path, max_alerts=1)
    assert m["status"] == "failed"
    assert all("NotImplementedError" in v for v in m["failed_cells"].values())
    assert len(m["cell_results"]) == 3


def test_git_commit_and_finished_runs(tmp_path):
    assert ex.git_commit()  # a hash, or "unknown (not a git repository)"
    assert ex.finished_runs(tmp_path / "missing.jsonl") == set()
    assert ex.package_versions()["langgraph"] != "not installed"


def test_cli_and_settings(tmp_path):
    ap = argparse.ArgumentParser()
    add_common_args(ap)
    s = apply_cli(deep_merge(DEFAULTS, {}), ap.parse_args(
        ["--guard", "on", "--topology", "hub", "--tool-mode", "llm", "--action-guard", "on"]))
    assert s["defense"]["name"] == "guard_v0" and s["pipeline"]["topology"] == "hub"
    assert s["pipeline"]["evidence_tool_mode"] == "llm" and s["action_guard"]["enabled"]
    s = apply_cli(deep_merge(DEFAULTS, {}), ap.parse_args(["--guard", "off", "--defense", "guard_v1"]))
    assert s["defense"]["name"] == "guard_v1"
    assert normalize(deep_merge(DEFAULTS, {"guard": {"enabled": True}}))["defense"]["name"] == "guard_v0"
    cfg = tmp_path / "s.yaml"
    cfg.write_text("llm: {backend: fake}\n")
    assert load_settings(cfg)["pipeline"]["topology"] == "chain"
    assert load_settings()["llm"]["backend"] == "fake"  # the shipped settings use the fake model
    setup_phoenix({"phoenix": {"enabled": False}})


def run_script(name: str, args: list[str], monkeypatch) -> int:
    monkeypatch.setattr(sys, "argv", [name, *args])
    try:
        runpy.run_path(str(SCRIPTS / name), run_name="__main__")
    except SystemExit as e:
        return int(e.code or 0)
    return 0


def test_check_llm_script(monkeypatch, capsys, mock_server):
    assert run_script("check_llm.py", ["--backend", "fake"], monkeypatch) == 0
    assert "backend : fake" in capsys.readouterr().out
    url = mock_server.url + "/v1"
    assert run_script("check_llm.py", ["--backend", "openai_compat", "--model", "m", "--base-url", url],
                      monkeypatch) == 0
    assert "127.0.0.1" in capsys.readouterr().out
    assert run_script("check_llm.py", ["--backend", "anthropic", "--model", "claude-haiku-5-5"], monkeypatch) == 1
    assert "ANTHROPIC_API_KEY" in capsys.readouterr().out


def test_validate_and_dry_run_scripts(monkeypatch, capsys, tmp_path):
    good = tmp_path / "good.jsonl"
    good.write_text(json.dumps({"schema_version": "1.1", "run_id": "r", "alert_id": "A", "goal": "NONE", "hop": 1,
                                "agent": "triage", "kind": "agent", "marker_found": False, "laundered": False,
                                "text": "", "time": 1.0}) + "\n")
    assert run_script("validate_trace.py", [str(tmp_path)], monkeypatch) == 0
    assert "0 schema errors" in capsys.readouterr().out
    (tmp_path / "bad.jsonl").write_text('{"run_id": "r"}\n')
    assert run_script("validate_trace.py", [str(tmp_path)], monkeypatch) == 1
    assert run_script("run_experiment.py", [str(SCRIPTS.parent / "experiments/smoke_fake.yaml"), "--dry-run"],
                      monkeypatch) == 0
    assert "315 cells" in capsys.readouterr().out


def test_download_script(monkeypatch, capsys):
    import soclab.data.download as dl

    monkeypatch.setattr(dl, "download", lambda name: (Path(f"/x/{name}"), "recorded"))
    assert run_script("download_data.py", ["loghub_openssh", "aitlds", "nope"], monkeypatch) == 1
    out = capsys.readouterr().out
    assert "new SHA-256" in out and "zenodo.org/records/5789064" in out and "Unknown dataset" in out

    def boom(name):
        raise ValueError("SHA-256 mismatch")

    monkeypatch.setattr(dl, "download", boom)
    assert run_script("download_data.py", [], monkeypatch) == 1
    assert "FAILED" in capsys.readouterr().out
