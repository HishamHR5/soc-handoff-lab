"""The SOC agents. One generic function runs any agent step.

Each step reads: the alert header (trusted metadata), the raw log lines (Triage only),
the messages of earlier steps (after the defense), and tool results (Evidence only).
The graph (graph.py) connects the steps and calls the tracer.

Evidence tool modes:
  fixed  the code calls siem_search, then ip_reputation (Phase I behavior)
  llm    the model chooses the tools: it writes TOOL_CALL lines (text format, the same for
         every backend), and gets TOOL_RESULT blocks back
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from . import prompts
from .action_guard import ActionGuard
from .defenses import Defense
from .siem import LocalSIEM
from .tools import Tool, call_tool, format_call
from .tracer import Tracer

LISTED_TOOLS = ["siem_search", "ip_reputation", "get_log"]  # the tools named in the prompt
TOOL_CALL_RE = re.compile(r"TOOL_CALL\s*:\s*", re.I)
LABEL = r"(true[\s_-]?positive|benign[\s_-]?positive|false[\s_-]?positive|TP|BP|FP)"
VERDICT_RES = [
    re.compile(r'"verdict"\s*:\s*"' + LABEL + r'"', re.I),
    re.compile(r"\bverdict\b[\s*_:=\-\"'`]*" + LABEL + r"\b", re.I),
]
SEVERITY_RES = [
    re.compile(r'"severity"\s*:\s*"(low|medium|high|critical)"', re.I),
    re.compile(r"\bseverity\b[\s*_:=\-\"'`]*(low|medium|high|critical)\b", re.I),
]
PHRASES = {"true positive": "TP", "benign positive": "BP", "false positive": "FP"}


@dataclass(frozen=True)
class Step:
    name: str  # node name; the tracer "agent" field
    role: str  # prompt: triage | evidence | investigator | investigator_b | judge | coordinator | reporter
    hop: int  # 1 Triage, 2 Evidence, 3 Investigator, 4 Reporter
    inputs: tuple[str, ...] = ()  # earlier steps whose messages this step reads
    reads_logs: bool = False
    uses_tools: bool = False
    gives_verdict: bool = False


@dataclass
class Ctx:
    """Everything that the steps of ONE run need."""

    llm: Any  # has .chat(system, user) -> LLMResponse
    siem: LocalSIEM
    tracer: Tracer
    defense: Defense
    action_guard: ActionGuard
    tools: dict[str, Tool]
    tool_mode: str = "fixed"
    max_tool_steps: int = 4
    max_logs: int = 40
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentOutput:
    text: str
    verdict: str | None = None
    severity: str | None = None


# --------------------------------------------------------------------------- parsing


def _last_match(regexes: list[re.Pattern[str]], text: str) -> str | None:
    best: tuple[int, str] | None = None
    for rx in regexes:
        for m in rx.finditer(text):
            if best is None or m.start() >= best[0]:
                best = (m.start(), m.group(1))
    return best[1] if best else None


def normalize_label(label: str) -> str:
    low = re.sub(r"[\s_-]+", " ", label.lower())
    return PHRASES.get(low, label.upper())


def parse_verdict(text: str) -> str | None:
    """TP, BP or FP from the agent text, or None. The LAST verdict statement wins.

    Accepts "VERDICT: TP", "**Verdict:** benign positive", '"verdict": "FP"'. If there is no
    verdict statement, a single kind of label phrase ("false positive") is also accepted.
    """
    label = _last_match(VERDICT_RES, text)
    if label:
        return normalize_label(label)
    found = {PHRASES[p] for p in PHRASES if re.search(p.replace(" ", r"[\s_-]?"), text, re.I)}
    return found.pop() if len(found) == 1 else None


def parse_severity(text: str) -> str | None:
    sev = _last_match(SEVERITY_RES, text)
    return sev.lower() if sev else None


def parse_tool_call(text: str) -> tuple[str, dict[str, Any]] | None:
    m = TOOL_CALL_RE.search(text)
    if not m:
        return None
    start = text.find("{", m.end())
    try:
        obj, _ = json.JSONDecoder().raw_decode(text[start:]) if start >= 0 else (None, 0)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict) or not isinstance(obj.get("name"), str):
        return None
    args = obj.get("arguments") or {}
    return (obj["name"], args) if isinstance(args, dict) else None


# --------------------------------------------------------------------------- prompts


def system_prompt(step: Step, ctx: Ctx) -> str:
    text = prompts.ROLE_PROMPTS[step.role]
    if step.uses_tools and ctx.tool_mode == "llm":
        listed = "\n".join(f"- {ctx.tools[n].description}" for n in LISTED_TOOLS)
        text += prompts.TOOL_MODE.format(tools=listed)
    return text + ctx.defense.system_suffix(step.role)


def user_prompt(step: Step, state: dict[str, Any], ctx: Ctx) -> str:
    alert = state["alert"]
    parts = [f"ALERT {alert['alert_id']}: {alert['rule']} (source IP {alert['src_ip']}, "
             f"log source {alert['source']})"]
    if step.reads_logs:
        lines = ctx.siem.logs_for_alert(alert, limit=ctx.max_logs)
        parts.append("LOGS:\n" + ctx.defense.render_logs(lines))
    messages = state.get("messages", {})
    for name in step.inputs:
        if name in messages:
            parts.append(f"MESSAGE FROM {name.upper()}:\n{messages[name]}")
    return "\n\n".join(parts)


# --------------------------------------------------------------------------- tools


def run_tool(step: Step, name: str, args: dict[str, Any], ctx: Ctx) -> str:
    """Run one tool call through the action guard, log it, and wrap the output."""
    tool = ctx.tools.get(name)
    egress = bool(tool and tool.network)
    reason = ctx.action_guard.check(step.role, tool, name, args)
    if reason:
        ctx.tracer.log(step.hop, "action_guard", "guard", format_call(name, args), guard_action="block",
                       reason=reason, detector="action_guard", tool=name, blocked_tool=name,
                       egress_attempt=egress, guarded_agent=step.name)
        return f"ERROR: the tool call was blocked by policy ({reason})."
    out = call_tool(ctx.tools, name, args)
    ctx.tracer.log(step.hop, step.name, "tool", out, tool=name, tool_args=args, egress_attempt=egress)
    return ctx.defense.wrap_tool_output(name, out)


def _evidence_fixed(step: Step, system: str, user: str, ip: str, ctx: Ctx) -> str:
    search = run_tool(step, "siem_search", {"ip": ip}, ctx)
    rep = run_tool(step, "ip_reputation", {"ip": ip}, ctx)
    user += f"\n\nTOOL siem_search({ip}):\n{search}\n\nTOOL ip_reputation({ip}):\n{rep}"
    text: str = ctx.llm.chat(system, user).text
    return text


def _evidence_llm(step: Step, system: str, user: str, ctx: Ctx) -> str:
    transcript = user
    for _ in range(ctx.max_tool_steps):
        answer: str = ctx.llm.chat(system, transcript).text
        call = parse_tool_call(answer)
        if call is None:
            return answer
        name, args = call
        result = run_tool(step, name, args, ctx)
        transcript += f"\n\n{answer.strip()}\nTOOL_RESULT {name}:\n{result}"
    final: str = ctx.llm.chat(system, transcript + "\n\nGive your final answer now. Do not call more tools.").text
    return final


def run_step(step: Step, state: dict[str, Any], ctx: Ctx) -> AgentOutput:
    system, user = system_prompt(step, ctx), user_prompt(step, state, ctx)
    if step.uses_tools and ctx.tool_mode == "llm":
        text = _evidence_llm(step, system, user, ctx)
    elif step.uses_tools:
        text = _evidence_fixed(step, system, user, state["alert"]["src_ip"], ctx)
    else:
        text = ctx.llm.chat(system, user).text
    if step.gives_verdict:
        return AgentOutput(text, parse_verdict(text), parse_severity(text))
    return AgentOutput(text)
