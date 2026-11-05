"""Run an experiment matrix (model x topology x defense x goal x variant x repeats).

  python scripts/run_experiment.py experiments/smoke_fake.yaml
  python scripts/run_experiment.py experiments/smoke_fake.yaml --workers 8
  python scripts/run_experiment.py experiments/claude_pilot.yaml --dry-run

Start it again after a crash: finished runs are skipped.
Output: runs/<name>/cells/*.jsonl and runs/<name>/manifest.json
Then:   python scripts/analyze.py runs/<name> --out results/<name>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from soclab.experiment import expand, load_experiment, run_experiment


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("experiment", type=Path)
    ap.add_argument("--workers", type=int, help="cells in parallel (default: the file's 'workers')")
    ap.add_argument("--max-alerts", type=int, help="use only the first N alerts of each dataset")
    ap.add_argument("--dry-run", action="store_true", help="list the cells and stop")
    a = ap.parse_args()

    if a.dry_run:
        cells = expand(load_experiment(a.experiment))
        print("\n".join(c.cell_id for c in cells))
        print(f"{len(cells)} cells")
        return 0
    manifest = run_experiment(a.experiment, workers=a.workers, max_alerts=a.max_alerts)
    print(f"\nStatus: {manifest['status']}. {len(manifest['cell_results'])}/{manifest['cells']} cells done, "
          f"{len(manifest['failed_cells'])} failed.")
    print(f"Next: python scripts/analyze.py runs/{manifest['experiment']} --out results/{manifest['experiment']}")
    return 0 if manifest["status"] == "complete" else 1


if __name__ == "__main__":
    sys.exit(main())
