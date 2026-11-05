"""Tables (CSV + LaTeX booktabs) and charts (PNG + PDF) for the thesis."""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .metrics import CONFIG_COLS, GROUP_COLS, HOPS  # noqa: E402

MAIN_METRICS = ["asr_end", "depth", "laundering_rate", "verdict_change_rate", "guard_detection_rate"]
CLEAN_METRICS = ["clean_accuracy", "guard_fp_rate"]
PERCENT = {"asr_end", "laundering_rate", "verdict_change_rate", "guard_detection_rate", "clean_accuracy",
           "guard_fp_rate", "unknown_rate", "egress_rate"} | {f"asr_hop{h}" for h in HOPS}
LATEX_ESCAPES = {"\\": r"\textbackslash{}", "&": r"\&", "%": r"\%", "$": r"\$", "#": r"\#", "_": r"\_",
                 "{": r"\{", "}": r"\}", "~": r"\textasciitilde{}", "^": r"\textasciicircum{}"}


def latex_escape(text: str) -> str:
    return "".join(LATEX_ESCAPES.get(ch, ch) for ch in str(text))


def fmt_ci(metric: str, value: float, lo: float, hi: float) -> str:
    if pd.isna(value):
        return "--"
    if metric in PERCENT:
        return f"{value * 100:.1f} [{lo * 100:.1f}, {hi * 100:.1f}]"
    return f"{value:.2f} [{lo:.2f}, {hi:.2f}]"


def to_booktabs(df: pd.DataFrame, caption: str, label: str) -> str:
    """A LaTeX table with booktabs rules (needs \\usepackage{booktabs})."""
    cols = list(df.columns)
    lines = [r"\begin{table}[htbp]", r"\centering", r"\small", rf"\caption{{{latex_escape(caption)}}}",
             rf"\label{{{label}}}", r"\begin{tabular}{" + "l" * len(cols) + "}", r"\toprule",
             " & ".join(latex_escape(c) for c in cols) + r" \\", r"\midrule"]
    lines += [" & ".join(latex_escape(v) for v in row) + r" \\" for row in df.astype(str).itertuples(index=False)]
    lines += [r"\bottomrule", r"\end{tabular}", r"\end{table}"]
    return "\n".join(lines) + "\n"


def wide_table(long: pd.DataFrame, metrics: list[str], keys: list[str]) -> pd.DataFrame:
    """One row per group, one column per metric, cells "value [low, high]"."""
    part = long[long.metric.isin(metrics)].copy()
    if part.empty:
        return pd.DataFrame(columns=keys + metrics)
    part["cell"] = [fmt_ci(m, v, lo, hi) for m, v, lo, hi in
                    zip(part.metric, part.value, part.ci_low, part.ci_high, strict=True)]
    n = part.groupby(keys).n.max().rename("n_runs")
    wide = part.pivot_table(index=keys, columns="metric", values="cell", aggfunc="first")
    wide = wide.reindex(columns=[m for m in metrics if m in wide.columns]).join(n).reset_index()
    return wide.fillna("--")


def save_table(df: pd.DataFrame, out_dir: Path, name: str, caption: str) -> None:
    df.to_csv(out_dir / f"{name}.csv", index=False)
    (out_dir / f"{name}.tex").write_text(to_booktabs(df, caption, f"tab:{name}"))


def write_tables(long: pd.DataFrame, out_dir: Path) -> dict[str, pd.DataFrame]:
    tables = {
        "main_attacked": wide_table(long, MAIN_METRICS, GROUP_COLS),
        "main_clean": wide_table(long, CLEAN_METRICS, CONFIG_COLS),
        "spread_per_hop": wide_table(long, [f"asr_hop{h}" for h in HOPS], GROUP_COLS),
        "overhead": wide_table(long, ["tokens_in", "tokens_out", "latency_s", "llm_calls", "cost_usd",
                                      "unknown_rate", "egress_rate"], GROUP_COLS),
    }
    captions = {
        "main_attacked": "Attack results per configuration (%, depth in hops; mean [95% CI]).",
        "main_clean": "Clean runs: accuracy and guard false-positive rate (%, mean [95% CI]).",
        "spread_per_hop": "Attacked runs where the payload reached each hop (%, mean [95% CI]).",
        "overhead": "Overhead per run (mean [95% CI]).",
    }
    for name, df in tables.items():
        save_table(df, out_dir, name, captions[name])
    return tables


def _save(fig: plt.Figure, out_dir: Path, name: str) -> None:
    fig.tight_layout()
    for ext in ("png", "pdf"):
        fig.savefig(out_dir / f"{name}.{ext}", dpi=150)
    plt.close(fig)


def plot_spread(runs: pd.DataFrame, out_dir: Path, by: str = "defense") -> None:
    """Payload spread per hop (attacked runs), one line per value of `by`, with 95% CIs."""
    from .metrics import bootstrap_ci

    att = runs[runs.attacked]
    fig, ax = plt.subplots(figsize=(6.5, 4))
    for value, g in att.groupby(by):
        stats = [bootstrap_ci(g[f"spread_h{h}"].astype(float).to_numpy(), g.alert_id.to_numpy()) for h in HOPS]
        mean = np.array([s[0] for s in stats]) * 100
        err = np.array([[s[0] - s[1], s[2] - s[0]] for s in stats]).T * 100
        ax.errorbar(HOPS, mean, yerr=err, marker="o", capsize=3, label=str(value))
    ax.set_xticks(HOPS, ["1 Triage", "2 Evidence", "3 Investigator", "4 Reporter"])
    ax.set_ylabel("Attacked runs with the payload (%)")
    ax.set_ylim(-5, 105)
    ax.legend(title=by, fontsize=8)
    _save(fig, out_dir, "spread_per_hop")


def plot_asr(runs: pd.DataFrame, out_dir: Path) -> None:
    """End-of-pipeline ASR per defense and goal, with 95% CIs."""
    from .metrics import bootstrap_ci

    att = runs[runs.attacked]
    goals = sorted(att.goal.unique())
    defenses = sorted(att.defense.unique())
    width = 0.8 / max(len(defenses), 1)
    fig, ax = plt.subplots(figsize=(7, 4))
    for i, d in enumerate(defenses):
        means, errs = [], []
        for goal in goals:
            g = att[(att.defense == d) & (att.goal == goal)]
            m, lo, hi = bootstrap_ci(g.attack_success.to_numpy(), g.alert_id.to_numpy())
            means.append(m * 100)
            errs.append([(m - lo) * 100, (hi - m) * 100])
        x = np.arange(len(goals)) + i * width
        ax.bar(x, means, width, yerr=np.array(errs).T, capsize=2, label=d)
    ax.set_xticks(np.arange(len(goals)) + width * (len(defenses) - 1) / 2, goals)
    ax.set_ylabel("Attack success at the end (%)")
    ax.set_ylim(0, 105)
    ax.legend(title="defense", fontsize=8)
    _save(fig, out_dir, "asr_by_defense")
