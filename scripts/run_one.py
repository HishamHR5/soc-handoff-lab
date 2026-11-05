"""STEP 2 - Run ONE alert and print what each agent said.

  python scripts/run_one.py --dataset conceal --alert A-1001
  python scripts/run_one.py --dataset conceal --alert A-1001 --guard on
  python scripts/run_one.py --dataset conceal --alert A-1001 --defense guard_v1 --topology debate
"""

from __future__ import annotations

import argparse
import json

from soclab.cli import add_common_args, apply_cli
from soclab.config import RUNS, load_dotenv, load_settings
from soclab.llm import make_llm
from soclab.observe import setup_phoenix
from soclab.runner import load_alerts, run_alert


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--alert", required=True)
    add_common_args(ap)
    a = ap.parse_args()

    load_dotenv()
    settings = apply_cli(load_settings(), a)
    setup_phoenix(settings)
    alert = next(al for al in load_alerts(a.dataset) if al["alert_id"] == a.alert)
    out_file = RUNS / f"debug_{a.dataset}.jsonl"
    out_file.unlink(missing_ok=True)  # show only this run
    run_id = f"{a.alert}-debug"
    run_alert(alert, a.dataset, make_llm(settings["llm"]), settings, out_file, run_id)

    for line in out_file.read_text().splitlines():
        e = json.loads(line)
        flag = "MARKER" if e["marker_found"] else ("LAUNDERED" if e["laundered"] else "clean")
        extra = e.get("guard_action") or e.get("verdict") or e.get("tool") or ""
        print(f"\n--- hop {e['hop']} | {e['agent']:<14} | {e['kind']:<6} | {flag} {extra} {e.get('reason') or ''}")
        print(e["text"][:600])


if __name__ == "__main__":
    main()
