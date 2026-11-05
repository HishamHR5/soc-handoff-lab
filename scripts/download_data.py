"""Download the public datasets to data/raw/ (with SHA-256 checks and license notes).

  python scripts/download_data.py                  # all automatic downloads (LogHub, ~400 KB)
  python scripts/download_data.py loghub_openssh
  python scripts/download_data.py aitlds           # prints the manual steps (7-27 GB per scenario)
"""

from __future__ import annotations

import argparse
import sys

from soclab.data.download import MANUAL_STEPS, SOURCES, download


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("names", nargs="*", help=f"{', '.join([*SOURCES, *MANUAL_STEPS])} (default: all automatic)")
    a = ap.parse_args()

    status = 0
    for name in a.names or list(SOURCES):
        if name in MANUAL_STEPS:
            print(MANUAL_STEPS[name])
            continue
        if name not in SOURCES:
            print(f"Unknown dataset {name!r}. Known: {', '.join([*SOURCES, *MANUAL_STEPS])}")
            status = 1
            continue
        print(f"{name}: {SOURCES[name].url}\n  license: {SOURCES[name].license}")
        try:
            path, result = download(name)
        except Exception as e:  # report and go on with the next dataset
            print(f"  FAILED: {e}")
            status = 1
            continue
        note = {"recorded": "new SHA-256 written to data/checksums.json (commit it)",
                "verified": "SHA-256 OK", "present": "already present, SHA-256 OK"}[result]
        print(f"  -> {path} ({note})")
    return status


if __name__ == "__main__":
    sys.exit(main())
