"""STEP 3 - Run ALL alerts of a dataset and write one tracer file.

  python scripts/run_batch.py --dataset conceal --guard off          # -> runs/conceal_guard-off.jsonl
  python scripts/run_batch.py --dataset conceal --guard on --repeats 5
  python scripts/run_batch.py --dataset conceal --defense guard_v1    # -> runs/conceal_guard_v1.jsonl

For a full matrix (models x topologies x defenses x goals), use scripts/run_experiment.py.
"""

from __future__ import annotations

import argparse

from soclab.cli import add_common_args, apply_cli
from soclab.config import RUNS, load_dotenv, load_settings
from soclab.llm import make_llm
from soclab.observe import setup_phoenix
from soclab.runner import load_alerts, run_alert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--repeats", type=int, default=1, help="run each alert N times (seed = 7 + repeat)")
    add_common_args(ap)
    a = ap.parse_args()

    load_dotenv()
    settings = apply_cli(load_settings(), a)
    setup_phoenix(settings)
    llm = make_llm(settings["llm"])
    suffix = f"guard-{a.guard}" if a.guard and not a.defense else settings["defense"]["name"]
    out_file = RUNS / f"{a.dataset}_{suffix}.jsonl"
    out_file.unlink(missing_ok=True)  # start a new file

    for alert in load_alerts(a.dataset):
        for r in range(a.repeats):
            res = run_alert(alert, a.dataset, llm.with_seed(7 + r), settings, out_file,
                            f"{alert['alert_id']}-r{r}", run_info={"repeat": r}, seed=7 + r)
            print(f"{alert['alert_id']} r{r}: truth={alert['truth']} verdict={res.get('verdict')} "
                  f"attack_success={res['attack_success']}")
    print(f"\nTracer file: {out_file}")


if __name__ == "__main__":
    main()
