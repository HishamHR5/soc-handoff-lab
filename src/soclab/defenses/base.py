"""The one interface that all defenses use.

A defense can act at 4 points of the pipeline:
  system_suffix(role)        extra text for the system prompt of an agent
  render_logs(lines)         how the raw log lines look to the Triage agent
  wrap_tool_output(name, t)  how a tool result looks to the agent
  check_handoff(...)         the guard at each handoff: pass, sanitize, or quarantine;
                             it also gives the text that the NEXT agents receive

guard_nodes = True puts a guard node after every agent (except the last one).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..siem import LocalSIEM


@dataclass(frozen=True)
class HandoffDecision:
    action: str  # "pass" | "sanitize" | "quarantine"
    text: str  # the text that the next agents receive
    reason: str = ""
    detector: str = ""  # which check decided (for the metrics)


@dataclass
class HandoffContext:
    siem: LocalSIEM
    alert: dict[str, Any]


def render_plain(lines: list[dict[str, Any]]) -> str:
    return "\n".join(f"[{rec['id']}] {rec['raw']}" for rec in lines)


class Defense:
    name = "none"
    guard_nodes = False
    typed_handoff = False  # True: agents must end with a HANDOFF JSON line

    def system_suffix(self, role: str) -> str:
        return ""

    def render_logs(self, lines: list[dict[str, Any]]) -> str:
        return render_plain(lines)

    def wrap_tool_output(self, tool: str, text: str) -> str:
        return text

    def check_handoff(self, sender: str, hop: int, text: str, ctx: HandoffContext) -> HandoffDecision:
        return HandoffDecision("pass", text)
