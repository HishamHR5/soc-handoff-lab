"""Build the LangGraph pipeline for a topology.

Topologies (pipeline.topology):
  chain   triage -> evidence -> investigator -> reporter
  hub     specialists talk only through a coordinator:
          triage -> coordinator_1 -> evidence -> coordinator_2 -> investigator -> coordinator_3 -> reporter
  debate  triage -> evidence -> investigator_a -> investigator_b (skeptic, sees A) -> judge -> reporter

With a defense that uses guard nodes, a guard node follows every agent except the last:
  agent -> guard -> next agent      (the guard can stop the run: guard -> END, "quarantined")
The guard decides what the next agents receive (defenses/base.py).
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypedDict

from langgraph.graph import END, START, StateGraph

from .agents import Ctx, Step, run_step
from .defenses import HandoffContext


class PipelineState(TypedDict, total=False):
    alert: dict[str, Any]
    messages: dict[str, str]  # step name -> the text that the next agents receive
    verdict: str
    severity: str
    report: str
    quarantined_at: str
    quarantined_agent: str


TOPOLOGIES: dict[str, list[Step]] = {
    "chain": [
        Step("triage", "triage", 1, (), reads_logs=True),
        Step("evidence", "evidence", 2, ("triage",), uses_tools=True),
        Step("investigator", "investigator", 3, ("triage", "evidence"), gives_verdict=True),
        Step("reporter", "reporter", 4, ("triage", "evidence", "investigator")),
    ],
    "hub": [
        Step("triage", "triage", 1, (), reads_logs=True),
        Step("coordinator_1", "coordinator", 1, ("triage",)),
        Step("evidence", "evidence", 2, ("coordinator_1",), uses_tools=True),
        Step("coordinator_2", "coordinator", 2, ("coordinator_1", "evidence")),
        Step("investigator", "investigator", 3, ("coordinator_2",), gives_verdict=True),
        Step("coordinator_3", "coordinator", 3, ("coordinator_2", "investigator")),
        Step("reporter", "reporter", 4, ("coordinator_3",)),
    ],
    "debate": [
        Step("triage", "triage", 1, (), reads_logs=True),
        Step("evidence", "evidence", 2, ("triage",), uses_tools=True),
        Step("investigator_a", "investigator", 3, ("triage", "evidence"), gives_verdict=True),
        Step("investigator_b", "investigator_b", 3, ("triage", "evidence", "investigator_a"), gives_verdict=True),
        Step("judge", "judge", 3, ("investigator_a", "investigator_b"), gives_verdict=True),
        Step("reporter", "reporter", 4, ("triage", "evidence", "judge")),
    ],
}


def _agent_node(step: Step, ctx: Ctx) -> Callable[[PipelineState], dict[str, Any]]:
    def node(state: PipelineState) -> dict[str, Any]:
        out = run_step(step, dict(state), ctx)
        update: dict[str, Any] = {"messages": {**state.get("messages", {}), step.name: out.text}}
        extra: dict[str, Any] = {}
        if step.gives_verdict:  # the last verdict step (investigator / judge) gives the final verdict
            update["verdict"] = extra["verdict"] = out.verdict or "UNKNOWN"
            update["severity"] = extra["severity"] = out.severity or "unknown"
            extra["verdict_parsed"] = out.verdict is not None
        if step.role == "reporter":
            update["report"] = out.text
        ctx.tracer.log(step.hop, step.name, "agent", out.text, **extra)
        return update

    return node


def _guard_node(step: Step, ctx: Ctx) -> Callable[[PipelineState], dict[str, Any]]:
    def node(state: PipelineState) -> dict[str, Any]:
        text = state["messages"][step.name]
        decision = ctx.defense.check_handoff(step.name, step.hop, text, HandoffContext(ctx.siem, state["alert"]))
        ctx.tracer.log(step.hop, f"guard_{step.hop}", "guard", text, guard_action=decision.action,
                       reason=decision.reason, detector=decision.detector, guarded_agent=step.name)
        if decision.action == "quarantine":
            return {"quarantined_at": f"guard_{step.hop}", "quarantined_agent": step.name, "verdict": "ESCALATE"}
        return {"messages": {**state["messages"], step.name: decision.text}}

    return node


def _route(state: PipelineState) -> str:
    return "stop" if state.get("quarantined_at") else "go"


def build_graph(ctx: Ctx, topology: str = "chain") -> Any:
    if topology not in TOPOLOGIES:
        raise ValueError(f"unknown topology {topology!r}; use one of {sorted(TOPOLOGIES)}")
    steps = TOPOLOGIES[topology]
    g = StateGraph(PipelineState)
    g.add_edge(START, steps[0].name)
    for i, step in enumerate(steps):
        g.add_node(step.name, _agent_node(step, ctx))  # type: ignore[call-overload]
        if i == len(steps) - 1:
            g.add_edge(step.name, END)
            break
        nxt = steps[i + 1].name
        if ctx.defense.guard_nodes:
            guard = f"guard_{step.name}"
            g.add_node(guard, _guard_node(step, ctx))  # type: ignore[call-overload]
            g.add_edge(step.name, guard)
            g.add_conditional_edges(guard, _route, {"go": nxt, "stop": END})
        else:
            g.add_edge(step.name, nxt)
    return g.compile()
