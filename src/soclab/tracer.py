"""The propagation tracer. It writes ONE JSON line for each event.

Event kinds:
  agent  - text that an agent sends to the next hop
  tool   - text that a tool gives to an agent (entry point 2)
  guard  - a guard decision (pass / sanitize / quarantine), or a blocked action (block)
  result - the final verdict of one run

For each text it checks:
  marker_found - the unique payload marker is in the text (verbatim spread)
  laundered    - no marker, but the payload idea is there (restated spread);
                 laundered_by says which methods found it (laundering.py)

The fields of README section 6 are fixed. New fields can be added; then raise
SCHEMA_VERSION and update src/soclab/schemas/tracer_event.schema.json.
"""

from __future__ import annotations

import json
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from .laundering import KeywordDetector, LaunderingChecker
from .llm import UsageMeter

SCHEMA_VERSION = "1.1"
SCHEMA_FILE = Path(__file__).resolve().parent / "schemas" / "tracer_event.schema.json"
EMPTY_USAGE = {"llm_calls": 0, "tokens_in": 0, "tokens_out": 0, "latency_s": 0.0, "cost_usd": None,
               "cached_calls": 0}
_FILE_LOCKS: dict[str, threading.Lock] = defaultdict(threading.Lock)


class Tracer:
    def __init__(self, out_file: Path, run_id: str, alert: dict[str, Any],
                 launder_keywords: list[str] | None = None, *, run_info: dict[str, Any] | None = None,
                 checker: LaunderingChecker | None = None, meter: UsageMeter | None = None):
        self.out_file = Path(out_file)
        self.out_file.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.alert = alert
        self.marker = alert.get("marker")
        self.run_info = run_info or {}
        self.meter = meter
        payload = alert.get("payload_plain") or alert.get("payload") or ""
        self.checker = checker or LaunderingChecker(self.marker, payload,
                                                    [KeywordDetector(launder_keywords or [])])

    def check(self, text: str) -> tuple[bool, bool]:
        """(marker_found, laundered) with the configured methods."""
        r = self.checker.check(text)
        return r["marker_found"], r["laundered"]

    def log(self, hop: int, agent: str, kind: str, text: str = "", **extra: Any) -> dict[str, Any]:
        analysis = self.checker.check(text, kind)
        # LLM usage goes on the next agent/guard/result event (not on tool events),
        # so the calls of a tool-using agent are counted on that agent's event.
        usage = self.meter.take() if (self.meter and kind != "tool") else dict(EMPTY_USAGE)
        event = {
            "schema_version": SCHEMA_VERSION,
            "run_id": self.run_id,
            "alert_id": self.alert["alert_id"],
            "goal": self.alert.get("goal", "NONE"),
            "hop": hop,
            "agent": agent,
            "kind": kind,
            "marker_found": analysis["marker_found"],
            "laundered": analysis["laundered"],
            "laundered_by": analysis["laundered_by"],
            "launder_score": analysis["launder_score"],
            "text": text,
            "time": round(time.time(), 3),
            "variant": self.alert.get("variant", "none"),
            **self.run_info,
            **usage,
            **extra,
        }
        line = json.dumps(event) + "\n"
        with _FILE_LOCKS[str(self.out_file)], open(self.out_file, "a") as f:
            f.write(line)
        return event


def load_schema() -> dict[str, Any]:
    schema: dict[str, Any] = json.loads(SCHEMA_FILE.read_text())
    return schema


def validate_file(path: Path) -> list[str]:
    """Validate each line of a tracer file. Return a list of errors (empty = valid)."""
    import jsonschema

    validator = jsonschema.Draft202012Validator(load_schema())
    errors = []
    with open(path) as f:
        for n, line in enumerate(f, start=1):
            if not line.strip():
                continue
            for err in validator.iter_errors(json.loads(line)):
                errors.append(f"{path.name}:{n}: {err.json_path}: {err.message}")
    return errors
