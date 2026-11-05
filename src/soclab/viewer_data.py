"""Data helpers for the Propagation Viewer (viewer/app.py). No Streamlit code here, so it can be tested.

Colors (the plan in the context file):
  green  = clean          red  = marker found (verbatim spread)
  orange = laundered      grey = quarantined / blocked
  blue   = guard that passed or sanitized
Each fill has a text color with a contrast of 4.5:1 or more (WCAG AA), and each agent or
tool node also shows its status in words, so the graph does not depend on color alone.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from collections import defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

from .config import DATA, DEFAULTS, RUNS, deep_merge
from .data.build import build_dataset
from .llm import LLM
from .runner import load_alerts, run_alert

COLORS = {"clean": "#1f7a33", "marker": "#d62728", "laundered": "#ff8c00", "stopped": "#6b6b6b",
          "guard": "#3b6aa8", "result": "#444444"}
DARK_TEXT = "#1a1a1a"
TEXT_COLORS = {k: DARK_TEXT if k == "laundered" else "#ffffff" for k in COLORS}  # white on orange is 2.3:1
FADED = {"fill": "#dddddd", "text": "#555555"}  # events after the current step
STATUS_WORDS = {"clean": "no payload", "marker": "PAYLOAD COPIED", "laundered": "REWORDED"}
HOP_NAMES = {1: "Triage", 2: "Evidence", 3: "Investigator", 4: "Reporter", 5: "End"}

PER_ROW = 5  # graph nodes in one row (a run with no guard fits); longer runs continue below
MARKER_RE = re.compile(r"ZX[A-Z0-9]{6}")  # the payload marker format (payloads.new_marker)
MIN_COPY = 20  # a run of this many characters from the payload counts as copied text


def read_events(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def trace_files(root: Path = RUNS) -> list[Path]:
    """All tracer files under runs/, newest first."""
    return sorted(root.rglob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True)


def list_runs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """One summary row per run (from its result event), in file order."""
    rows = []
    for e in events:
        if e["kind"] == "result":
            rows.append({"run_id": e["run_id"], "alert_id": e["alert_id"], "goal": e["goal"],
                         "variant": e.get("variant", "none"), "topology": e.get("topology", "chain"),
                         "defense": e.get("defense", "?"), "truth": e["truth"], "verdict": e["verdict"],
                         "attack_success": e["attack_success"], "quarantined_at": e.get("quarantined_at")})
    return rows


def run_events(events: list[dict[str, Any]], run_id: str, cell_id: str | None = None) -> list[dict[str, Any]]:
    return [e for e in events if e["run_id"] == run_id and (cell_id is None or e.get("cell_id") == cell_id)]


def status(e: dict[str, Any]) -> str:
    """clean | marker | laundered | stopped | guard | result"""
    if e["kind"] == "guard":
        return "stopped" if e.get("guard_action") in ("quarantine", "block") else "guard"
    if e["kind"] == "result":
        return "stopped" if e.get("verdict") == "ESCALATE" else "result"
    if e["marker_found"]:
        return "marker"
    return "laundered" if e["laundered"] else "clean"


def node_label(e: dict[str, Any], step: int) -> str:
    """The text in a graph node: step number, name, then verdict or status."""
    if e["kind"] == "guard":
        return f"{step} · {e['agent']}\n{e.get('guard_action', '')}"
    if e["kind"] == "result":
        return f"{step} · END\nverdict {e.get('verdict')}\ntruth {e.get('truth')}"
    name = f"tool: {e.get('tool', '?')}" if e["kind"] == "tool" else e["agent"]
    lines = [f"{step} · {name}"]
    if e.get("verdict"):
        lines.append(f"verdict {e['verdict']}")
    lines.append(STATUS_WORDS[status(e)])
    return "\n".join(lines)


def graph_layout(events: list[dict[str, Any]], upto: int, selected: int | None = None
                 ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Node and edge rows for the run graph (0-based event indexes).

    The main events form a chain, left to right, PER_ROW nodes per row. Each tool event
    sits below the agent that used it. Events after `upto` are faded.
    """
    chain = [i for i, e in enumerate(events) if e["kind"] != "tool"]
    tools_of: dict[int, list[int]] = defaultdict(list)
    for i, e in enumerate(events):
        if e["kind"] == "tool":
            owner = next((j for j in chain if j > i and events[j]["agent"] == e["agent"]),
                         next((j for j in chain if j > i), chain[-1] if chain else i))
            tools_of[owner].append(i)

    pos: dict[int, tuple[float, float]] = {}
    gap_y: dict[float, float] = {}  # row y -> y of the free space below the row and its tools
    y = 0.0
    for start in range(0, len(chain), PER_ROW):
        row = chain[start:start + PER_ROW]
        for col, i in enumerate(row):
            pos[i] = (float(col), y)
            for k, t in enumerate(tools_of[i]):
                pos[t] = (float(col), y - (k + 1))
        depth = max(len(tools_of[i]) for i in row)
        gap_y[y] = y - depth - 0.75
        y -= depth + 1.5

    nodes = []
    for i, e in enumerate(events):
        faded = i > upto
        s = status(e)
        x, ny = pos[i]
        nodes.append({"step": i + 1, "x": x, "y": ny, "label": node_label(e, i + 1), "status": s,
                      "agent": e["agent"], "kind": e["kind"],
                      "fill": FADED["fill"] if faded else COLORS[s],
                      "text": FADED["text"] if faded else TEXT_COLORS[s],
                      "selected": i == selected})
    edges = []
    for a, b in zip(chain, chain[1:], strict=False):
        (xa, ya), (xb, yb) = pos[a], pos[b]
        if ya == yb:
            path = [(xa, ya), (xb, yb)]
        else:  # to the next row: go through the free space between the boxes, not over them
            mid = gap_y[ya]
            path = [(xa, ya), (xa + 0.5, ya), (xa + 0.5, mid), (xb - 0.5, mid), (xb - 0.5, yb), (xb, yb)]
        edges += [{"x": p[0], "y": p[1], "x2": q[0], "y2": q[1], "dashed": False}
                  for p, q in zip(path, path[1:], strict=False)]
    edges += [{"x": pos[t][0], "y": pos[t][1], "x2": pos[o][0], "y2": pos[o][1], "dashed": True}
              for o, ts in tools_of.items() for t in ts]
    return nodes, edges


def highlight_spans(text: str, payload: str | None, keywords: list[str]) -> list[tuple[int, int, str]]:
    """Parts of `text` to mark, as (start, end, kind), in order, not overlapping.

    kind "copied" : the payload marker, or MIN_COPY+ characters copied from the payload.
    kind "keyword": a laundering keyword of the goal (the payload idea in other words).
    "copied" wins where both match.
    """
    labels: list[str | None] = [None] * len(text)
    low = text.lower()
    for k in keywords:
        for m in re.finditer(re.escape(k.lower()), low):
            labels[m.start():m.end()] = ["keyword"] * (m.end() - m.start())
    copied = [(m.start(), m.end()) for m in MARKER_RE.finditer(text)]
    if payload:
        matcher = SequenceMatcher(None, text, payload, autojunk=False)
        copied += [(b.a, b.a + b.size) for b in matcher.get_matching_blocks() if b.size >= MIN_COPY]
    for start, end in copied:
        labels[start:end] = ["copied"] * (end - start)

    spans: list[tuple[int, int, str]] = []
    for i, label in enumerate(labels):
        if label is None:
            continue
        if spans and spans[-1][1] == i and spans[-1][2] == label:
            spans[-1] = (spans[-1][0], i + 1, label)
        else:
            spans.append((i, i + 1, label))
    return spans


def highlight_html(text: str, payload: str | None, keywords: list[str]) -> str:
    """The text as safe HTML, with the highlight_spans in <mark> tags."""
    style = {"copied": (COLORS["marker"], TEXT_COLORS["marker"]),
             "laundered": (COLORS["laundered"], TEXT_COLORS["laundered"])}
    out, last = [], 0
    for start, end, kind in highlight_spans(text, payload, keywords):
        bg, fg = style["copied" if kind == "copied" else "laundered"]
        out.append(html.escape(text[last:start]))
        out.append(f'<mark title="{kind}" style="background:{bg};color:{fg};padding:0 2px;'
                   f'border-radius:3px">{html.escape(text[start:end])}</mark>')
        last = end
    out.append(html.escape(text[last:]))
    return "".join(out)


def describe(e: dict[str, Any]) -> str:
    """One line that explains the event in plain words."""
    s = status(e)
    if e["kind"] == "guard":
        what = {"pass": "let the message through", "sanitize": "removed instruction-like text",
                "quarantine": "STOPPED the run (sent to a human)", "block": "BLOCKED a tool call"}
        return f"Guard {what.get(e.get('guard_action', ''), '')}. {e.get('reason') or ''}".strip()
    if e["kind"] == "result":
        ok = e.get("attack_success")
        outcome = "attack SUCCEEDED" if ok else ("attack failed" if ok is False else "clean run")
        return f"Final verdict {e.get('verdict')} (truth {e.get('truth')}): {outcome}."
    where = "Tool output" if e["kind"] == "tool" else "Agent message"
    return {"marker": f"{where} contains the payload marker (verbatim spread).",
            "laundered": f"{where} restates the payload without the marker (laundered, found by "
                         f"{', '.join(e.get('laundered_by') or ['keywords'])}).",
            "clean": f"{where} has no payload."}[s]


def ensure_dataset(source: str, goal: str, variant: str, field: str | None, seed: int = 7,
                   root: Path = DATA / "datasets", custom_text: str | None = None) -> Path:
    """Build (once) the dataset that the viewer runs on."""
    name = f"viewer_{source}_{goal}_{variant}_{field or 'default'}_{seed}"
    if custom_text:
        name += "_custom" + hashlib.sha256(custom_text.encode()).hexdigest()[:10]
    path = root / name
    if not (path / "info.json").exists():
        build_dataset({"source": source, "n": 2}, goal, variant, seed, path, field, custom_text=custom_text)
    return path


def live_run(alert: dict[str, Any], dataset: Path, llm: LLM, options: dict[str, Any],
             out_file: Path) -> list[dict[str, Any]]:
    """Run one alert with the chosen options; return its events."""
    settings = deep_merge(DEFAULTS, {
        "pipeline": {"topology": options["topology"], "evidence_tool_mode": options["tool_mode"]},
        "defense": {"name": options["defense"]},
        "action_guard": {"enabled": options["action_guard"]},
    })
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.unlink(missing_ok=True)
    run_alert(alert, dataset, llm, settings, out_file, f"{alert['alert_id']}-live")
    return read_events(out_file)


__all__ = ["COLORS", "FADED", "HOP_NAMES", "STATUS_WORDS", "TEXT_COLORS", "describe", "ensure_dataset",
           "graph_layout", "highlight_html", "highlight_spans", "list_runs", "live_run", "load_alerts",
           "node_label", "read_events", "run_events", "status", "trace_files"]
