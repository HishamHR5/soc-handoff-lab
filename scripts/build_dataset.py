"""STEP 1 - Make a dataset (clean or attacked).

  python scripts/build_dataset.py --goal NONE    --name clean
  python scripts/build_dataset.py --goal CONCEAL --name conceal
  python scripts/build_dataset.py --goal EXFIL   --name exfil_b64 --variant encoded --source synthetic
  python scripts/build_dataset.py --goal INSTRUCT --name instr_ref --field referer --source synthetic

Output: data/datasets/<name>/logs.jsonl, alerts.jsonl, ip_reputation.json, info.json
"""

from __future__ import annotations

import argparse

from soclab.config import DATA
from soclab.data.build import build_dataset
from soclab.payloads import GOALS, VARIANTS


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--goal", default="NONE", choices=["NONE", *GOALS])
    ap.add_argument("--name", required=True)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--variant", default="direct", choices=VARIANTS)
    ap.add_argument("--source", default="samples",
                    choices=["samples", "synthetic", "loghub_openssh", "loghub_apache"],
                    help="aitlds needs a dataset block in an experiment file (see README)")
    ap.add_argument("--n", type=int, default=2, help="synthetic: scenarios of each type")
    ap.add_argument("--max-alerts", type=int, help="real datasets: keep at most N alerts (balanced)")
    ap.add_argument("--field", help="attacker field: ssh_username, user_agent, url_path, query_string, referer")
    a = ap.parse_args()

    spec = {"source": a.source, "n": a.n, "max_alerts": a.max_alerts}
    out = DATA / "datasets" / a.name
    info = build_dataset(spec, a.goal, a.variant, a.seed, out, a.field)
    print(f"Dataset '{a.name}': {info['n_logs']} log lines, {info['n_alerts']} alerts, "
          f"goal={a.goal}, variant={a.variant} -> {out}")


if __name__ == "__main__":
    main()
