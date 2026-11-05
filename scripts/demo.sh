#!/usr/bin/env bash
# A 2-minute demo with the FAKE model (no key, no network). The numbers are NOT results.
#   bash scripts/demo.sh
set -e
cd "$(dirname "$0")/.."
source .venv/bin/activate
pause() { echo; read -r -p ">>> Press Enter for the next step: $1 " _; echo; }

pause "make a clean and an attacked (CONCEAL) dataset"
python scripts/build_dataset.py --goal NONE --name demo_clean
python scripts/build_dataset.py --goal CONCEAL --name demo_conceal
grep -h "ZX" data/datasets/demo_conceal/logs.jsonl | head -2

pause "attack with NO defense (watch MARKER -> LAUNDERED -> verdict BP)"
python scripts/run_one.py --dataset demo_conceal --alert A-1001 --defense none

pause "the same attack with guard_v0 (Phase I guard)"
python scripts/run_one.py --dataset demo_conceal --alert A-1001 --defense guard_v0

pause "the same attack with guard_v1 (typed handoff + claim-to-evidence)"
python scripts/run_one.py --dataset demo_conceal --alert A-1001 --defense guard_v1

pause "debate topology, no defense"
python scripts/run_one.py --dataset demo_conceal --alert A-1001 --topology debate

pause "a 'rogue' model tries a network upload; action guard OFF (sinkhole) then ON (blocked)"
python -c "
from soclab.config import DEFAULTS, deep_merge
from soclab.llm import make_llm
from soclab.runner import load_alerts, run_alert
from pathlib import Path
import json
for ag in (False, True):
    s = deep_merge(DEFAULTS, {'pipeline': {'evidence_tool_mode': 'llm'}, 'action_guard': {'enabled': ag}})
    out = Path('runs/demo_rogue.jsonl'); out.unlink(missing_ok=True)
    run_alert(load_alerts('demo_clean')[0], 'demo_clean', make_llm({'backend': 'fake', 'fake_behavior': 'rogue'}), s, out, 'rogue')
    print(f'--- action guard {\"ON\" if ag else \"OFF\"}')
    for line in out.read_text().splitlines():
        e = json.loads(line)
        if e.get('egress_attempt'):
            print(' ', e['kind'], e.get('guard_action') or '', '|', e['text'][:100])
"

pause "run all alerts with 3 defenses, then compute the metrics"
python scripts/run_batch.py --dataset demo_conceal --defense none
python scripts/run_batch.py --dataset demo_conceal --defense guard_v0
python scripts/run_batch.py --dataset demo_conceal --defense guard_v1
python scripts/analyze.py runs/demo_conceal_none.jsonl runs/demo_conceal_guard_v0.jsonl runs/demo_conceal_guard_v1.jsonl --out results/demo

echo
echo "Done. Charts: results/demo/spread_per_hop.png and results/demo/asr_by_defense.png"
echo "Big demo (315 cells, ~35 s): python scripts/run_experiment.py experiments/smoke_fake.yaml"
open results/demo/asr_by_defense.png 2>/dev/null || true
