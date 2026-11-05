"""Run the pipeline on one alert. Used by scripts/run_one.py, run_batch.py and run_experiment.py."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .action_guard import ActionGuard
from .agents import Ctx
from .config import DATA
from .defenses import make_defense
from .graph import build_graph
from .laundering import Encoder, make_checker
from .llm import LLM, MeteredLLM, UsageMeter
from .metrics import attack_success
from .payloads import load_templates
from .siem import LocalSIEM
from .tools import make_tools
from .tracer import Tracer


def dataset_dir(dataset: str | Path) -> Path:
    path = Path(dataset)
    return path if path.is_dir() else DATA / "datasets" / str(dataset)


def load_alerts(dataset: str | Path) -> list[dict[str, Any]]:
    with open(dataset_dir(dataset) / "alerts.jsonl") as f:
        return [json.loads(line) for line in f if line.strip()]


def run_alert(alert: dict[str, Any], dataset: str | Path, llm: LLM, settings: dict[str, Any],
              out_file: Path, run_id: str, *, run_info: dict[str, Any] | None = None,
              judge_llm: Any = None, encoder: Encoder | None = None, seed: int = 0) -> dict[str, Any]:
    """Run all agents on one alert. Write the events to out_file. Return the final state."""
    pipe = settings["pipeline"]
    defense_name = settings["defense"]["name"]
    siem = LocalSIEM(dataset_dir(dataset))
    goal = alert.get("goal", "NONE")
    keywords = load_templates().get(goal, {}).get("launder_keywords", [])
    meter = UsageMeter()
    info = {"topology": pipe["topology"], "defense": defense_name, "model": llm.model,
            "backend": llm.backend.name, "evidence_tool_mode": pipe["evidence_tool_mode"],
            "action_guard": bool(settings["action_guard"].get("enabled")), "seed": seed, **(run_info or {})}
    checker = make_checker(alert, keywords, settings.get("laundering"), encoder=encoder, judge_llm=judge_llm)
    tracer = Tracer(out_file, run_id, alert, run_info=info, checker=checker, meter=meter)
    ctx = Ctx(
        llm=MeteredLLM(llm, meter), siem=siem, tracer=tracer, defense=make_defense(defense_name, seed),
        action_guard=ActionGuard(settings["action_guard"], llm.host), tools=make_tools(siem),
        tool_mode=pipe["evidence_tool_mode"], max_tool_steps=int(pipe["max_tool_steps"]),
        max_logs=int(pipe["max_logs_per_alert"]),
    )
    graph = build_graph(ctx, pipe["topology"])
    final = graph.invoke({"alert": alert, "messages": {}}, {"recursion_limit": 60})

    verdict = final.get("verdict", "UNKNOWN")
    report = final.get("report", "")
    success = attack_success(goal, alert["truth"], verdict, report, alert.get("marker"))
    tracer.log(5, "end", "result", report, verdict=verdict, truth=alert["truth"], attack_success=success,
               quarantined_at=final.get("quarantined_at"), quarantined_agent=final.get("quarantined_agent"),
               severity=final.get("severity", "unknown"))
    return {**final, "attack_success": success}
