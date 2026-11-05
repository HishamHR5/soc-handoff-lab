"""STEP 4 - Calculate the metrics, tables and charts.

  python scripts/analyze.py runs/conceal_none.jsonl runs/conceal_guard_v0.jsonl
  python scripts/analyze.py runs/smoke_fake                 # an experiment folder
  python scripts/analyze.py runs/smoke_fake --out results/smoke_fake

Output folder (default results/<name of the first input>):
  runs.csv            one row per run
  summary_long.csv    every metric per group, with 95% bootstrap CI (clusters = alerts)
  main_attacked.csv/.tex, main_clean.csv/.tex, spread_per_hop.csv/.tex, overhead.csv/.tex
  spread_per_hop.png/.pdf, asr_by_defense.png/.pdf
"""

from __future__ import annotations

import argparse
from pathlib import Path

from soclab.config import RESULTS
from soclab.metrics import load_events, runs_table, summary_long
from soclab.report import plot_asr, plot_spread, write_tables


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("inputs", nargs="+", help="tracer files (*.jsonl) or folders")
    ap.add_argument("--out", help="output folder")
    ap.add_argument("--n-boot", type=int, default=2000)
    a = ap.parse_args()

    out = Path(a.out) if a.out else RESULTS / Path(a.inputs[0]).stem
    out.mkdir(parents=True, exist_ok=True)
    events = load_events(a.inputs)
    runs = runs_table(events)
    long = summary_long(runs, a.n_boot)
    runs.to_csv(out / "runs.csv", index=False)
    long.to_csv(out / "summary_long.csv", index=False)
    tables = write_tables(long, out)
    if runs.attacked.any():
        plot_spread(runs, out)
        plot_asr(runs, out)

    print(f"{len(runs)} runs ({int(runs.attacked.sum())} attacked, {int((~runs.attacked).sum())} clean)\n")
    for name in ("main_attacked", "main_clean"):
        if not tables[name].empty:
            print(f"=== {name} (%, mean [95% CI]) ===")
            print(tables[name].to_string(index=False), "\n")
    print(f"Tables and charts: {out}")


if __name__ == "__main__":
    main()
