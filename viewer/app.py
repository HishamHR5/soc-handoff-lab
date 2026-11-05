"""Propagation Viewer: see how a log-borne payload moves across the SOC agent handoffs.

  pip install -e ".[viewer]"
  streamlit run viewer/app.py          # opens http://localhost:8501

Tabs:
  Run an attack      choose alert, goal, payload (built-in or your own text), topology, defense;
                     run it; click a node or press Play to step through the hops
  Open a trace file  replay any run in runs/ (run_batch.py, run_experiment.py)
  Metrics            ASR, spread per hop, clean accuracy for a whole experiment folder
"""

from __future__ import annotations

import os
from html import escape
from pathlib import Path
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

from soclab.config import RUNS, load_dotenv, load_settings
from soclab.defenses import DEFENSES
from soclab.fields import ATTACKER_FIELDS
from soclab.graph import TOPOLOGIES
from soclab.llm import LLMError, make_llm
from soclab.metrics import HOPS, load_events, runs_table, summary_long
from soclab.payloads import CUSTOM_MAX_CHARS, VARIANTS, load_templates
from soclab.report import CLEAN_METRICS, MAIN_METRICS, wide_table
from soclab.viewer_data import (
    COLORS,
    TEXT_COLORS,
    describe,
    ensure_dataset,
    graph_layout,
    highlight_html,
    list_runs,
    live_run,
    load_alerts,
    read_events,
    run_events,
    status,
    trace_files,
)

OUT = Path(os.environ.get("SOCLAB_VIEWER_OUT", RUNS / "viewer"))
WORKING_DEFENSES = [d for d in DEFENSES if d not in ("g_safeguard", "paul_nandy")]
FIELDS = ["default"] + sorted({f for fields in ATTACKER_FIELDS.values() for f in fields})
MODELS = {"fake (gullible)": {"backend": "fake", "fake_behavior": "gullible"},
          "fake (rogue: tries a network upload)": {"backend": "fake", "fake_behavior": "rogue"},
          "model in config/settings.yaml": None}
TEMPLATES = load_templates()
PLAY_SECONDS = 1.2  # time per step when Play is on
ROW_PX, LINE_PX = 90, 14  # graph: pixels per row, pixels per text line
MESSAGE_STYLE = ("white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace;font-size:0.9rem;"
                 "line-height:1.5;padding:12px;border-radius:8px;background:rgba(128,128,128,0.12)")

st.set_page_config(page_title="Propagation Viewer", page_icon=":material/shield:", layout="wide")
st.title("SOC Handoff Lab: Propagation Viewer")
st.caption("How attacker text in a log moves Triage → Evidence → Investigator → Reporter. "
           "Numbers from the fake model are NOT results.")


def legend() -> None:
    items = [("clean", "no payload"), ("marker", "payload copied (marker)"),
             ("laundered", "payload reworded"), ("stopped", "quarantined / blocked"),
             ("guard", "guard passed")]
    html = " ".join(f'<span style="background:{COLORS[k]};color:{TEXT_COLORS[k]};padding:2px 8px;'
                    f'border-radius:6px;margin-right:6px;font-size:0.9em">{label}</span>' for k, label in items)
    st.markdown(html, unsafe_allow_html=True)


def graph_chart(events: list[dict[str, Any]], step: int) -> alt.LayerChart:
    """The run graph. The top layer is invisible boxes that catch clicks (param "node")."""
    nodes, edges = graph_layout(events, upto=step, selected=step)
    nd, ed = pd.DataFrame(nodes), pd.DataFrame(edges)
    cols = int(nd.x.max()) + 1
    xs = alt.Scale(domain=[-0.55, cols - 0.45])
    ys = alt.Scale(domain=[float(nd.y.min()) - 0.5, 0.5])
    x, y = alt.X("x:Q", axis=None, scale=xs), alt.Y("y:Q", axis=None, scale=ys)
    box = {"x": alt.X("x0:Q", axis=None, scale=xs), "x2": "x1:Q",
           "y": alt.Y("y0:Q", axis=None, scale=ys), "y2": "y1:Q"}
    base = alt.Chart(nd).transform_calculate(x0="datum.x - 0.43", x1="datum.x + 0.43",
                                             y0="datum.y - 0.36", y1="datum.y + 0.36")
    lines = alt.Chart(ed).mark_rule(color="#999999", strokeWidth=2).encode(
        x=x, y=y, x2="x2:Q", y2="y2:Q",
        strokeDash=alt.condition("datum.dashed", alt.value([5, 4]), alt.value([1, 0])))
    fills = base.mark_rect(cornerRadius=8).encode(
        **box, color=alt.Color("fill:N", scale=None),
        stroke=alt.condition("datum.selected", alt.value("#f5c518"), alt.value("transparent")),
        strokeWidth=alt.condition("datum.selected", alt.value(4), alt.value(0)))
    # One text row per label line, centered in the box (Altair does not center multi-line text).
    step_y = LINE_PX / ROW_PX
    lines_df = pd.DataFrame([{"x": n["x"], "y": n["y"] + ((len(rows) - 1) / 2 - k) * step_y, "line": line,
                              "text": n["text"]}
                             for n in nodes for rows in [n["label"].split("\n")] for k, line in enumerate(rows)])
    labels = alt.Chart(lines_df).mark_text(fontSize=11, baseline="middle").encode(
        x=x, y=y, text="line:N", color=alt.Color("text:N", scale=None))
    pick = alt.selection_point(name="node", fields=["step"], on="click", empty=False)
    hits = base.mark_rect(opacity=0, cursor="pointer").encode(
        **box, tooltip=[alt.Tooltip("step:Q"), alt.Tooltip("agent:N"), alt.Tooltip("kind:N"),
                        alt.Tooltip("status:N")]).add_params(pick)
    return alt.layer(lines, fills, labels, hits).properties(
        height=int((1 - float(nd.y.min())) * ROW_PX))  # the width follows the page


def show_run(events: list[dict[str, Any]], key: str, payload: str | None = None) -> None:
    """Graph + Play + step slider + details of one run. Click a node to open its step."""
    if not events:
        st.info("No events.")
        return
    n = len(events)
    step_key, play_key, skip_key = f"{key}_step", f"{key}_playing", f"{key}_skip_tick"
    run_id = (events[0]["run_id"], events[0].get("time"), n)
    if st.session_state.get(f"{key}_run") != run_id:  # a new run: show its end, stop playing
        st.session_state.update({f"{key}_run": run_id, step_key: n, play_key: False})
    playing = st.session_state[play_key]
    result = events[-1] if events[-1]["kind"] == "result" else {}
    goal = events[0].get("goal", "NONE")
    keywords = TEMPLATES.get(goal, {}).get("launder_keywords", [])

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Truth", result.get("truth", "?"))
    c2.metric("Final verdict", result.get("verdict", "?"))
    success = result.get("attack_success")
    c3.metric("Attack success", "clean run" if success is None else ("YES" if success else "no"))
    c4.metric("Stopped at", result.get("quarantined_at") or "no")

    def toggle_play() -> None:
        if st.session_state[play_key]:
            st.session_state[play_key] = False
        else:  # start from step 1; the first timer tick must not skip it
            st.session_state.update({play_key: True, step_key: 1, skip_key: True})

    @st.fragment(run_every=PLAY_SECONDS if playing else None)
    def body() -> None:
        if st.session_state[play_key] != playing:  # Play/Pause changed: set the timer on or off
            st.rerun()
        if st.session_state[play_key]:
            if st.session_state.pop(skip_key, False):
                pass  # the Play click itself: stay on step 1
            elif st.session_state[step_key] < n:
                st.session_state[step_key] += 1
            else:  # the end: stop the timer with a full rerun
                st.session_state[play_key] = False
                st.rerun()

        b, s = st.columns([1, 6], vertical_alignment="bottom")
        b.button("Pause" if st.session_state[play_key] else "Play", key=f"{key}_play",
                 icon=":material/pause:" if st.session_state[play_key] else ":material/play_arrow:",
                 on_click=toggle_play, width="stretch",
                 help="Show the steps one by one")
        s.slider("Step through the run (or click a node)", 1, n, key=step_key)
        step = st.session_state[step_key] - 1
        legend()

        chart_key = f"{key}_graph_{step}"  # a new key per step, so a click on any node always counts

        def on_pick() -> None:
            picked = st.session_state[chart_key].selection.get("node", [])
            if picked:
                st.session_state.update({step_key: int(picked[0]["step"]), play_key: False})

        st.altair_chart(graph_chart(events, step), key=chart_key, on_select=on_pick,
                        selection_mode="node", width="stretch")

        e = events[step]
        st.markdown(f"#### Step {step + 1}: hop {e['hop']} · {e['agent']} · {e['kind']}")
        st.markdown(f"**{describe(e)}**")
        info = {"status": status(e), "tokens in/out": f"{e.get('tokens_in', 0)}/{e.get('tokens_out', 0)}",
                "LLM calls": e.get("llm_calls", 0)}
        if e.get("tool"):
            info["tool"] = e["tool"]
        if e.get("detector"):
            info["detector"] = e["detector"]
        st.caption(" · ".join(f"{k}: {v}" for k, v in info.items()))
        if goal != "NONE":
            source = "the payload text" if payload else "the payload marker"
            st.caption(f"Highlights: red = copied from {source}; orange = a keyword of the {goal} payload "
                       "idea (reworded).")
        text = e["text"] or "(empty)"
        body_html = highlight_html(text, payload, keywords) if goal != "NONE" else escape(text)
        st.markdown(f'<div style="{MESSAGE_STYLE}">{body_html}</div>', unsafe_allow_html=True)

    body()

    with st.expander("All events of this run"):
        table = pd.DataFrame([{"step": i + 1, "hop": x["hop"], "agent": x["agent"], "kind": x["kind"],
                               "status": status(x), "guard": x.get("guard_action") or "",
                               "reason": x.get("reason") or "", "text": x["text"][:120]}
                              for i, x in enumerate(events)])
        st.dataframe(table, hide_index=True, width="stretch")


# --------------------------------------------------------------------------- tab 1: run
tab_run, tab_file, tab_metrics = st.tabs(["Run an attack", "Open a trace file", "Metrics"])

with tab_run:
    left, right = st.columns([1, 3])
    with left:
        st.markdown("##### Attack")
        source = st.selectbox("Logs", ["samples", "synthetic"], help="samples = 4 Phase I alerts")
        goal = st.selectbox("Attack goal", ["CONCEAL", "FABRICATE", "EXFIL", "INSTRUCT", "NONE"],
                            help="NONE = clean run (no payload)")
        own = st.toggle("Write your own payload", disabled=goal == "NONE")
        custom = None
        if own and goal != "NONE":
            custom = st.text_area(
                "Attacker text", TEMPLATES[goal]["text"], max_chars=CUSTOM_MAX_CHARS, height=110,
                help="{marker} is where the unique tracking code goes. If you leave it out, it is added "
                     "at the end. The goal still decides what counts as attack success.")
            if not custom.strip():
                st.warning("Write some attacker text.")
        variant = st.selectbox("Payload variant", VARIANTS, disabled=goal == "NONE" or custom is not None,
                               help="Your own text is used as written (variant direct).")
        field = st.selectbox("Attacker field", FIELDS, disabled=goal == "NONE",
                             help="default: SSH username for auth.log, user agent for access.log")
        alerts = []
        if custom is None or custom.strip():
            dataset = ensure_dataset(source, goal, "direct" if goal == "NONE" or custom else variant,
                                     None if field == "default" else field, custom_text=custom)
            alerts = load_alerts(dataset)
        if not alerts and (custom is None or custom.strip()):
            st.warning("No alert can carry this payload in this field. Choose another field or source.")
        labels = {f"{a['alert_id']} · {a['rule'][:38]} · truth {a['truth']}": a for a in alerts}
        alert = labels[st.selectbox("Alert", list(labels))] if alerts else None
        st.markdown("##### Pipeline")
        topology = st.selectbox("Topology", list(TOPOLOGIES))
        defense = st.selectbox("Defense", WORKING_DEFENSES)
        tool_mode = st.radio("Evidence tools", ["fixed", "llm"], horizontal=True,
                             help="llm = the model chooses the tools")
        action_guard = st.checkbox("Action guard (tool allowlist + egress deny)")
        model = st.selectbox("Model", list(MODELS))
        clicked = st.button("Run", type="primary", key="run", disabled=alert is None, width="stretch")

    with right:
        if clicked and alert is not None:
            try:
                load_dotenv()
                cfg = MODELS[model] or load_settings()["llm"]
                llm = make_llm(cfg)
                with st.spinner(f"Running {alert['alert_id']} with {llm.model} ..."):
                    st.session_state["live"] = live_run(
                        alert, dataset, llm,
                        {"topology": topology, "defense": defense, "tool_mode": tool_mode,
                         "action_guard": action_guard},
                        OUT / "live.jsonl")
                    st.session_state["live_alert"] = alert
            except (LLMError, NotImplementedError) as err:
                st.error(str(err))
        if "live" in st.session_state:
            shown = st.session_state["live_alert"]  # the alert of the run on screen
            if shown.get("payload"):
                st.caption(f"Payload in the log: `{shown['payload'][:CUSTOM_MAX_CHARS]}`")
            show_run(st.session_state["live"], "live", shown.get("payload_plain"))
        else:
            st.info("Choose the options on the left, then click **Run**.")

# --------------------------------------------------------------------------- tab 2: replay
with tab_file:
    files = trace_files(RUNS)
    if not files:
        st.info("No tracer files in runs/ yet. Run scripts/run_batch.py or scripts/run_experiment.py.")
    else:
        names = [str(f.relative_to(RUNS)) for f in files]
        path = files[names.index(st.selectbox("Tracer file (newest first)", names))]
        events = read_events(path)
        run_rows = list_runs(events)
        if run_rows:
            frame = pd.DataFrame(run_rows)
            st.dataframe(frame, hide_index=True, width="stretch", height=220)
            pick = st.selectbox("Run", range(len(run_rows)), format_func=lambda i: (
                f"{run_rows[i]['run_id']} · {run_rows[i]['goal']}/{run_rows[i]['variant']} · {run_rows[i]['defense']} · "
                f"verdict {run_rows[i]['verdict']} (truth {run_rows[i]['truth']})"))
            show_run(run_events(events, run_rows[pick]["run_id"]), "file")

# --------------------------------------------------------------------------- tab 3: metrics


@st.cache_data(show_spinner="Computing metrics ...")
def compute(path: str, mtime: float) -> tuple[pd.DataFrame, pd.DataFrame]:
    runs = runs_table(load_events(path))
    return runs, summary_long(runs, n_boot=500)


with tab_metrics:
    folders = sorted([p for p in RUNS.iterdir() if p.is_dir() and any(p.rglob("*.jsonl"))] if RUNS.exists() else [])
    if not folders:
        st.info("No experiment folders in runs/. Run: python scripts/run_experiment.py experiments/smoke_fake.yaml")
    else:
        folder = st.selectbox("Experiment folder", folders, format_func=lambda p: p.name)
        mtime = max(f.stat().st_mtime for f in folder.rglob("*.jsonl"))
        exp_runs, long = compute(str(folder), mtime)
        att = exp_runs[exp_runs.attacked]
        st.caption(f"{len(exp_runs)} runs ({len(att)} attacked, {len(exp_runs) - len(att)} clean). "
                   "95% CIs: bootstrap over alerts.")
        cols = st.columns(4)
        filters = {}
        for col, name in zip(cols, ["model", "topology", "goal", "variant"], strict=True):
            values = sorted(exp_runs[name].unique())
            filters[name] = col.multiselect(name.capitalize(), values, default=values)
        by = st.radio("Lines by", ["defense", "topology", "goal", "variant", "model"], horizontal=True)
        sel = att
        for name, values in filters.items():
            sel = sel[sel[name].isin(values)]
        if sel.empty:
            st.warning("No attacked runs match the filters.")
        else:
            spread = sel.groupby(by)[[f"spread_h{h}" for h in HOPS]].mean().T * 100
            spread.index = ["1 Triage", "2 Evidence", "3 Investigator", "4 Reporter"]
            st.markdown("**Attacked runs with the payload at each hop (%)**")
            st.line_chart(spread)
            asr = sel.groupby(by).attack_success.mean() * 100
            st.markdown("**Attack success at the end (%)**")
            st.bar_chart(asr)
        mask = pd.Series(True, index=long.index)
        for name, values in filters.items():
            if name in ("goal", "variant"):
                mask &= long[name].isin(values) | (long.goal == "NONE")
            else:
                mask &= long[name].isin(values)
        st.markdown("**Attacked runs (%, mean [95% CI])**")
        st.dataframe(wide_table(long[mask], MAIN_METRICS, ["model", "topology", "defense", "goal", "variant"]),
                     hide_index=True, width="stretch")
        st.markdown("**Clean runs (%, mean [95% CI])**")
        st.dataframe(wide_table(long[mask], CLEAN_METRICS, ["model", "topology", "defense"]),
                     hide_index=True, width="stretch")
