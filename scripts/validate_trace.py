"""Validate tracer files against src/soclab/schemas/tracer_event.schema.json.

  python scripts/validate_trace.py runs/smoke_fake          # a folder: all *.jsonl files in it
  python scripts/validate_trace.py runs/conceal_guard-off.jsonl
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from soclab.tracer import validate_file


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+", type=Path)
    a = ap.parse_args()
    files = [f for p in a.paths for f in (sorted(p.rglob("*.jsonl")) if p.is_dir() else [p])]
    errors = [err for f in files for err in validate_file(f)]
    lines = sum(1 for f in files for line in f.read_text().splitlines() if line.strip())
    for err in errors[:50]:
        print(err)
    print(f"{len(files)} files, {lines} events, {len(errors)} schema errors")
    return 1 if errors or not files else 0


if __name__ == "__main__":
    sys.exit(main())
