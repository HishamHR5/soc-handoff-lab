# SOC Handoff Lab

A test lab for the M.Tech project **"Securing SOC Agent Pipelines Against Log-Borne Prompt Injection and Poisoned Agents"**
(Hisham R S, IIIT Kottayam).

The lab does 3 things:

1. It puts attacker text (a **payload**) into log fields that an attacker can write.
2. It runs a pipeline of LLM agents on the alert: **Triage → Evidence → Investigator → Reporter**
   (also as a **hub** with a coordinator, or a **debate** with 2 investigators and a judge).
3. It records each hop in a **tracer file**, so you can see how far the payload goes.

```
Attacker ─► log field ─► SIEM ─► Triage ─► [guard] ─► Evidence ─► [guard] ─► Investigator ─► [guard] ─► Reporter
                                    ▲                    ▲  ▲
                              entry point 1         tools: entry point 2
                                          (all hops are written to runs/*.jsonl by the tracer)
```

More: [ARCHITECTURE.md](ARCHITECTURE.md) (diagram and data flow), [DECISIONS.md](DECISIONS.md)
(every assumption, with items to check).

---

## 1. Folder structure

```
soc-handoff-lab/
├── README.md  ARCHITECTURE.md  DECISIONS.md
├── pyproject.toml             ← the package and its dependencies (pip install -e ".[dev]")
├── .env.example               ← copy to .env and put API keys there (never commit .env)
├── config/settings.yaml       ← CHANGE SETTINGS HERE: model, topology, defense, ...
├── experiments/*.yaml         ← experiment matrices (model × topology × defense × goal × variant)
├── payloads/templates.yaml    ← attack text: 4 goals × 5 variants
├── data/
│   ├── samples/               ← 4 hand-made alerts (Phase I)
│   ├── raw/                   ← downloaded datasets (LogHub, AIT-LDS, GUIDE); not in git
│   ├── checksums.json         ← SHA-256 of downloaded files (made on the first download)
│   └── datasets/              ← made by build_dataset.py / run_experiment.py
├── src/soclab/
│   ├── config.py              ← settings + .env loader
│   ├── llm.py  fake_llm.py    ← model backends (fake, openai_compat, openai, anthropic, gemini)
│   ├── mock_server.py         ← local mock LLM HTTP server (tests, no key needed)
│   ├── prompts.py             ← agent instructions (with the secret CANARY-SOC-7731)
│   ├── siem.py  tools.py      ← local SIEM; tools (http_request is a sinkhole)
│   ├── fields.py  payloads.py ← attacker-controlled fields; payload injection
│   ├── data/                  ← loaders (LogHub, AIT-LDS, GUIDE), synthetic logs, alert builder, downloads
│   ├── agents.py  graph.py    ← agents; LangGraph topologies chain / hub / debate
│   ├── defenses/              ← none, guard_v0, llm_tagging, layered, guard_v1 (+ 2 stubs)
│   ├── guard.py  detector.py  ← guard v0 (Phase I); injection detector
│   ├── action_guard.py        ← optional tool allowlist + default-deny egress
│   ├── tracer.py  laundering.py  schemas/   ← tracer, laundering detection, JSON Schema
│   ├── metrics.py  report.py  ← metrics with 95% CIs; CSV/LaTeX tables; PNG/PDF charts
│   ├── viewer_data.py         ← data helpers for the viewer (graph, colors)
│   ├── runner.py  experiment.py  cli.py  observe.py
├── scripts/                   ← YOU RUN THESE (see below)
├── viewer/app.py              ← Propagation Viewer (streamlit run viewer/app.py)
├── tests/                     ← pytest (no internet, no keys)
├── runs/   results/           ← outputs (not in git)
└── .github/workflows/ci.yml   ← lint, types, tests on each push
```

| Script | Job |
|---|---|
| `build_dataset.py` | step A: make a clean / attacked dataset |
| `run_one.py` | step B: run 1 alert, print each hop |
| `run_batch.py` | step C: run all alerts of a dataset → one tracer file |
| `analyze.py` | step D: metrics, tables (CSV + LaTeX), charts (PNG + PDF) |
| `run_experiment.py` | a full matrix, with resume and parallel cells |
| `check_llm.py` | send 1 test prompt to the configured model |
| `download_data.py` | download LogHub; print the AIT-LDS and GUIDE steps |
| `mock_llm_server.py` | local mock LLM server (OpenAI / Anthropic / Gemini formats) |
| `validate_trace.py` | check tracer files against the JSON Schema |
| `demo.sh` | a 2-minute guided demo with the fake model (`bash scripts/demo.sh`) |

---

## 2. Set up (one time)

```bash
git clone <repository URL> && cd soc-handoff-lab   # or: cd into your copy of the project folder
python3 -m venv .venv               # Python 3.10 or newer (on a Mac the command is python3)
source .venv/bin/activate           # do this in EACH new terminal; the prompt then starts with (.venv)
pip install -r requirements.txt     # = pip install -e ".[dev,viewer]"
pytest -q                           # all tests must pass (no internet, no key needed)
```

All commands in this README run **from the project folder, with `.venv` active**. Without
activation, write `.venv/bin/python` instead of `python` (see §14, Common errors).

Optional extras: `pip install -e ".[embeddings]"` (embedding-based laundering detection),
`pip install -e ".[phoenix]"` (Phoenix trace viewer).

---

## 3. Quick start with the FAKE model (no LLM needed)

`config/settings.yaml` starts with `backend: fake`. The fake model always obeys the payload.
It is **not a result**. It only shows that the pipeline, the tracer and the metrics work.

**2-minute guided demo** (it stops before each step; press Enter to go on):

```bash
bash scripts/demo.sh
```

It shows: the payload in the logs → spread with no defense → guard_v0 and guard_v1 stop it →
the debate topology → a "rogue" model that tries a network upload (sinkhole, then blocked by the
action guard) → metrics and a chart. For an interactive view, use the Propagation Viewer (§11).

The same steps by hand:

```bash
# A. Make datasets
python scripts/build_dataset.py --goal NONE    --name clean
python scripts/build_dataset.py --goal CONCEAL --name conceal

# B. Run one alert and read each hop
python scripts/run_one.py --dataset conceal --alert A-1001

# C. Run all alerts, with no guard and with the guards
python scripts/run_batch.py --dataset conceal --guard off           # runs/conceal_guard-off.jsonl
python scripts/run_batch.py --dataset conceal --guard on            # runs/conceal_guard-on.jsonl (guard_v0)
python scripts/run_batch.py --dataset conceal --defense guard_v1    # runs/conceal_guard_v1.jsonl

# D. Calculate the metrics
python scripts/analyze.py runs/conceal_guard-off.jsonl runs/conceal_guard-on.jsonl runs/conceal_guard_v1.jsonl --out results/conceal
```

Fake-model result of step D (test only): no guard → ASR 100 %, payload laundered from hop 2;
guard_v0 and guard_v1 → quarantined at hop 1, ASR 0 %.

### How to read the output of `run_one.py`

```
--- hop 1 | triage         | agent  | MARKER              ← agent copied the payload (marker found)
--- hop 2 | evidence       | tool   | MARKER siem_search  ← attacker text came in through a tool
--- hop 2 | evidence       | agent  | LAUNDERED           ← payload idea, but in the agent's own words
--- hop 3 | investigator   | agent  | LAUNDERED BP        ← verdict changed to "benign"
--- hop 5 | end            | result | clean BP            ← final verdict (truth was TP → attack success)
```

Other options: `--topology hub|debate`, `--defense none|guard_v0|llm_tagging|layered|guard_v1`,
`--tool-mode llm` (the model chooses the tools), `--action-guard on`.

---

## 4. Use a real model

API keys go in `.env` only (never in `settings.yaml`, never in git):

```bash
cp .env.example .env        # then edit .env, for example: ANTHROPIC_API_KEY=sk-ant-...
```

Then set the backend in `config/settings.yaml` (or in the `models:` list of an experiment file),
and check the connection with **one** call:

```bash
python scripts/check_llm.py                                              # the backend in settings.yaml
python scripts/check_llm.py --backend anthropic --model claude-haiku-5-5
```

| Backend | `llm.backend` | Key in `.env` | Example `model` | Notes |
|---|---|---|---|---|
| Claude | `anthropic` | `ANTHROPIC_API_KEY` | `claude-haiku-5-5`, `claude-sonnet-5-5` | temperature is never sent (API 2026-10-21); optional `effort: low` |
| OpenAI | `openai` | `OPENAI_API_KEY` | your model | `temperature: null` for models that accept only the default |
| Gemini | `gemini` | `GEMINI_API_KEY` | your model | |
| Ollama | `ollama` (= `openai_compat`) | none | `qwen2.5:0.5b`, `llama3.1:8b` | `base_url: http://localhost:11434/v1` |
| vLLM | `vllm` (= `openai_compat`) | none | `meta-llama/Llama-3.1-8B-Instruct` | `base_url: http://<server>:8000/v1` |
| LM Studio | `openai_compat` | none | the loaded model | `base_url: http://localhost:1234/v1` |

Ollama on the Mac:

```bash
ollama serve                         # if the app is not already running
ollama pull qwen2.5:0.5b             # small model for a smoke test (about 400 MB)
python scripts/check_llm.py --backend ollama --model qwen2.5:0.5b
python scripts/run_experiment.py experiments/ollama_smoke.yaml
```

vLLM on a GPU server: `vllm serve meta-llama/Llama-3.1-8B-Instruct --port 8000`.

Useful `llm:` settings: `requests_per_minute` (rate limit), `max_retries` and `backoff_base_s`
(retries for 429/5xx), `timeout_s`, `cache: {enabled: true}` (re-run without new API cost),
`price_in_per_mtok` / `price_out_per_mtok` (cost metric). Each call's tokens, latency and cost
go into the tracer.

---

## 5. Test logs (data)

| Source (`dataset.source`) | What | How to get it |
|---|---|---|
| `samples` | 4 hand-made alerts (Phase I) | in the repo |
| `synthetic` | SSH brute force, web scans, typos, IT scanner, health probes, normal traffic; fixed seed | made by the code |
| `loghub_openssh` | LogHub OpenSSH 2k lines (no labels: truth is heuristic) | `python scripts/download_data.py` |
| `loghub_apache` | LogHub Apache **error** log 2k lines (no labels) | `python scripts/download_data.py` |
| `aitlds` | AIT-LDS v2 auth.log + Apache access logs, with labels | manual: `python scripts/download_data.py aitlds` |
| `guide` | Microsoft GUIDE test file: real incidents with analyst labels (TP/BP/FP); anonymized table, no raw logs → **clean runs only** (`dataset: {source: guide, n: 20}` = 20 incidents per label; example: `experiments/guide_clean_fake.yaml`) | manual (Kaggle account): `python scripts/download_data.py guide` |

Alerts come from simple SIEM rules (`data/alerts.py`) with a ground-truth label TP / BP / FP
from the dataset labels. Payloads: 4 goals (CONCEAL, FABRICATE, EXFIL, INSTRUCT) × 5 variants
(direct, polite, hidden, split, encoded); attacker fields: `ssh_username`, `url_path`,
`query_string`, `user_agent`, `referer`.

```bash
python scripts/build_dataset.py --source synthetic --goal FABRICATE --variant split --name fab_split
python scripts/build_dataset.py --source synthetic --goal INSTRUCT --field referer --name instr_ref
```

---

## 6. The tracer file (the contract between all parts)

Each line in `runs/*.jsonl` is one event. These fields are fixed (Phase I); never rename them:

| Field | Meaning |
|---|---|
| `run_id` | one run of one alert, for example `A-1001-r0` |
| `alert_id`, `goal` | the alert and the attack goal (`NONE` for clean runs) |
| `hop` | 1 Triage, 2 Evidence, 3 Investigator, 4 Reporter, 5 end |
| `agent`, `kind` | who wrote it; `agent`, `tool`, `guard` or `result` |
| `marker_found` | the unique marker of the payload is in the text |
| `laundered` | no marker, but the payload idea is in the text |
| `text` | the full text |
| `time` | Unix time |
| `guard_action`, `reason` | guard events only: `pass`, `sanitize`, `quarantine` (or `block` from the action guard) |
| `verdict`, `truth`, `attack_success`, `quarantined_at` | result events only |

Fields added in Phase II (schema version 1.1): `schema_version`, `laundered_by`, `launder_score`,
`variant`, `topology`, `defense`, `model`, `backend`, `seed`, `repeat`, `experiment`, `cell_id`,
`llm_calls`, `tokens_in`, `tokens_out`, `latency_s`, `cost_usd`, `cached_calls`, `detector`,
`guarded_agent`, `tool_args`, `egress_attempt`, `blocked_tool`, `verdict_parsed`, `severity`, ...
The full list is the JSON Schema `src/soclab/schemas/tracer_event.schema.json`. Check files with:

```bash
python scripts/validate_trace.py runs/
```

---

## 7. Phase II tasks: status

| # | Task | Status |
|---|---|---|
| 1 | Real models; better prompts | Backends done (§4). Prompt tuning needs real-model runs: **to do**. |
| 2 | FABRICATE, EXFIL, INSTRUCT runs | Done: 4 goals × 5 variants (`payloads/templates.yaml`). |
| 3 | Real log loaders | Done: LogHub OpenSSH/Apache, AIT-LDS v2, Microsoft GUIDE (`src/soclab/data/`). |
| 4 | Better laundering detection | Done: keywords, embeddings, LLM judge (`laundering.py`). Thresholds: **calibrate**. |
| 5 | Guard v1 | Done (`defenses/guard_v1.py`). |
| 6 | Baselines | Done: LLM tagging, layered. G-Safeguard, Paul & Nandy: **documented stubs**. |
| 7 | Hub and debate topologies | Done (`graph.py`). |
| 8 | WazuhSIEM class | **To do** (same methods as `LocalSIEM`). |
| 9 | Propagation Viewer | Done: Streamlit app (`viewer/app.py`, §11). A React/Angular version: later, if needed. |
| – | Untrusted-model angle (RQ4) | Action guard + sinkhole tool + `rogue` fake model; OFF by default. |

---

## 8. Run an experiment

An experiment file lists models, topologies, defenses, goals, variants, repeats and the dataset.
A clean cell (goal `NONE`) is added for each model × topology × defense automatically.

```bash
python scripts/run_experiment.py experiments/smoke_fake.yaml --dry-run    # list the cells
python scripts/run_experiment.py experiments/smoke_fake.yaml              # 315 cells, ~1 min, fake model
python scripts/validate_trace.py runs/smoke_fake
python scripts/analyze.py runs/smoke_fake --out results/smoke_fake
```

- **Resume:** start the same command again after a crash. Finished runs are skipped; half-done
  runs are removed and done again.
- **Parallel:** `--workers N` runs N cells at the same time (a rate limit per model is shared).
- **Manifest:** `runs/<name>/manifest.json` has the config, git commit, seed, package versions,
  dataset SHA-256 hashes, start/end times and any failed cells.

The real-API path without a key (local mock server):

```bash
python scripts/mock_llm_server.py --port 8765 &          # or in a second terminal
python scripts/run_experiment.py experiments/smoke_mock.yaml
kill %1
```

Claude pilot (costs money; check the cell count first with `--dry-run`):
`python scripts/run_experiment.py experiments/claude_pilot.yaml`.

### Outputs of `analyze.py`

| File | Content |
|---|---|
| `runs.csv` | one row per run |
| `summary_long.csv` | every metric per group, with 95% bootstrap CI (clusters = alerts) |
| `main_attacked.csv/.tex` | ASR at the end, depth, laundering rate, verdict change rate, guard detection rate |
| `main_clean.csv/.tex` | clean accuracy, guard false-positive rate |
| `spread_per_hop.csv/.tex/.png/.pdf` | ASR per hop |
| `overhead.csv/.tex` | tokens, latency, cost, LLM calls, UNKNOWN-verdict rate, egress rate |
| `asr_by_defense.png/.pdf` | ASR per defense and goal |

The `.tex` tables use `booktabs` (`\usepackage{booktabs}`). Metric definitions: `src/soclab/metrics.py`.

---

## 9. Defenses

Select with `defense.name` (or `--defense`). All use one interface (`defenses/base.py`).

| Name | What it does |
|---|---|
| `none` | no defense |
| `guard_v0` | Phase I guard: fixed patterns + unknown log IDs → quarantine |
| `llm_tagging` | Lee & Tiwari (2024): agent messages are tagged with their source |
| `layered` | Karanjai et al. (2026) style: sanitization + random delimiters + instruction defense |
| `guard_v1` | thesis method: typed handoff (pydantic), provenance labels, injection detector, claim-to-evidence check, quarantine |
| `g_safeguard`, `paul_nandy` | documented stubs (not implemented; they stop with an error) |

Action guard (`action_guard.enabled: true`, or `--action-guard on`): per-agent tool allowlist and
default-deny network egress; each blocked call is logged. The network tool `http_request` is
always a sinkhole: no tool in this lab makes a real network call.

---

## 10. Tests and quality

```bash
pytest -q --cov=soclab        # coverage must be >= 85 %
ruff check .
mypy src
```

---

## 11. Propagation Viewer (interactive)

```bash
streamlit run viewer/app.py         # from the project folder, .venv active
.venv/bin/streamlit run viewer/app.py   # the same, without activation
```

Then open **http://127.0.0.1:8501**. Stop it with Ctrl+C. Streamlit is installed by
`requirements.txt` (or: `pip install -e ".[viewer]"`). Start it from the project folder:
`.streamlit/config.toml` there makes the viewer listen only on this computer (127.0.0.1) and
turns off Streamlit's usage statistics. Only one viewer can run at a time (port 8501).

| Tab | What you can do |
|---|---|
| Run an attack | Choose logs, goal, variant, attacker field, alert, topology, defense, tool mode, action guard and model; click **Run**. Turn on **Write your own payload** to type your own attacker text (max. 300 characters; `{marker}` is where the tracking code goes, else it is added at the end). |
| Open a trace file | Replay any run in `runs/` (from `run_batch.py` or `run_experiment.py`). |
| Metrics | For an experiment folder: payload spread per hop, ASR at the end, and the tables with 95% CIs, with filters. |

To move through a run: **click a node** in the graph, move the **slider**, or press **Play**
(one step every 1.2 s; **Pause** stops it). Each node shows its step number and its status in
words (PAYLOAD COPIED, REWORDED, no payload).

Colors: green = no payload, red = payload marker (verbatim), orange = payload in new words
(laundered), grey = quarantined or blocked, blue = guard passed. The yellow frame is the current
step; later steps are faded. All text colors have a contrast of 4.5:1 or more (WCAG AA).

Highlights in the message box: red = text copied from the payload (the marker, or 20+ characters
of the payload text); orange = a laundering keyword of the goal. In the "Open a trace file" tab
only the marker and the keywords are marked, because trace files do not store the payload text.
The model "model in config/settings.yaml" uses your real backend (it can cost money).

## 12. Phoenix (optional)

```bash
pip install -e ".[phoenix]"
phoenix serve                # open http://localhost:6006
```

Set `phoenix: enabled: true` in `config/settings.yaml`.

---

## 13. Known limits

- The fake model is a test tool only. Do not report its numbers.
- Laundering thresholds (embedding 0.6) and the LLM judge are not calibrated yet.
- guard_v1 rules are tuned on the fake model only. Measure its false-positive rate with real models.
- Tool calling uses a text protocol (`TOOL_CALL:`), the same for every backend, not native function calling.
- LogHub has no attack labels (heuristic truth). AIT-LDS needs a manual download (7–27 GB).
- G-Safeguard and Paul & Nandy are stubs. WazuhSIEM is not done.
- The action guard is a Python policy check, not an OS sandbox.
- See DECISIONS.md for all assumptions.

---

## 14. Common errors

| Error | Cause | Fix |
|---|---|---|
| `bash: scripts/demo.sh: No such file or directory` | The terminal is not in the project folder. | `cd` into the project folder (the folder with `README.md`). Put the path in quotes if it has a space. |
| `zsh: command not found: python` | `.venv` is not active (a Mac has only `python3`). | `source .venv/bin/activate`, or write `.venv/bin/python`. |
| `ModuleNotFoundError: No module named 'soclab'` | `.venv` is not active, or the package is not installed. | `source .venv/bin/activate`, then `pip install -r requirements.txt`. |
| `Port 8501 is not available` | A viewer already runs. | Use the running one (http://127.0.0.1:8501), or stop it with Ctrl+C in its terminal. |
| `The 'anthropic' backend needs the environment variable ANTHROPIC_API_KEY` | No key in `.env`. | `cp .env.example .env`, then put the key in `.env`. |
| Streamlit shows an external URL | It was started outside the project folder, so `.streamlit/config.toml` was not read. | Stop it; `cd` to the project folder; start it again. |

## License

The code is under the MIT License (see `LICENSE`). The datasets are **not** part of this
repository and keep their own licenses: LogHub (see its repository), AIT-LDS v2 (CC BY-NC-SA 4.0),
Microsoft GUIDE (the terms on its Kaggle page). The payloads are for defensive testing only.

