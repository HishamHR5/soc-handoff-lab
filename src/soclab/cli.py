"""Command-line options that run_one.py and run_batch.py share."""

from __future__ import annotations

import argparse
from typing import Any


def add_common_args(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--guard", choices=["on", "off"], help="old switch: on = guard_v0, off = none")
    ap.add_argument("--defense", help="none | guard_v0 | llm_tagging | layered | guard_v1")
    ap.add_argument("--topology", choices=["chain", "hub", "debate"])
    ap.add_argument("--tool-mode", choices=["fixed", "llm"])
    ap.add_argument("--action-guard", choices=["on", "off"])


def apply_cli(settings: dict[str, Any], a: argparse.Namespace) -> dict[str, Any]:
    """Command-line options win over settings.yaml."""
    if a.guard is not None:
        settings["defense"]["name"] = "guard_v0" if a.guard == "on" else "none"
    if a.defense:
        settings["defense"]["name"] = a.defense
    if a.topology:
        settings["pipeline"]["topology"] = a.topology
    if a.tool_mode:
        settings["pipeline"]["evidence_tool_mode"] = a.tool_mode
    if a.action_guard is not None:
        settings["action_guard"]["enabled"] = a.action_guard == "on"
    return settings
