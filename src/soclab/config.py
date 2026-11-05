"""Project paths, settings and secrets.

Settings come from config/settings.yaml. Missing keys get the values in DEFAULTS,
so an old or short settings file still works.

Secrets (API keys) come ONLY from environment variables. load_dotenv() reads the
file .env into the environment (it never overwrites a variable that is set).
"""

from __future__ import annotations

import copy
import os
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]  # project folder
DATA = ROOT / "data"
RUNS = ROOT / "runs"
RESULTS = ROOT / "results"
CACHE = ROOT / ".cache"

DEFAULTS: dict[str, Any] = {
    "llm": {
        # fake | openai_compat | openai | anthropic | gemini   ("ollama" and "vllm" = openai_compat)
        "backend": "fake",
        "model": "fake-gullible",
        "base_url": None,  # None = the default URL of the backend
        "api_key_env": None,  # None = the default variable of the backend
        "temperature": 0.0,  # None = do not send. The anthropic backend never sends it.
        "max_tokens": 1024,
        "seed": None,
        "effort": None,  # anthropic only: low | medium | high (None = model default)
        "timeout_s": 60.0,
        "max_retries": 5,
        "backoff_base_s": 1.0,
        "backoff_max_s": 60.0,
        "requests_per_minute": 0,  # 0 = no limit
        "price_in_per_mtok": None,  # USD per 1M input tokens. None = cost unknown.
        "price_out_per_mtok": None,
        "cache": {"enabled": False, "dir": str(CACHE / "llm")},
        "fake_behavior": "gullible",  # fake backend only: gullible | rogue
    },
    "pipeline": {
        "topology": "chain",  # chain | hub | debate
        "evidence_tool_mode": "fixed",  # fixed | llm  (llm = the model chooses the tools)
        "max_tool_steps": 4,
        "max_logs_per_alert": 40,
    },
    # none | guard_v0 | llm_tagging | layered | guard_v1 | g_safeguard (stub) | paul_nandy (stub)
    "defense": {"name": "none"},
    # Old setting. guard.enabled: true means defense guard_v0 (if defense.name is "none").
    "guard": {"enabled": False},
    "action_guard": {
        "enabled": False,
        "allowlist": {"evidence": ["siem_search", "ip_reputation", "get_log"]},
        "egress_allow_hosts": [],  # the LLM API host is always allowed
    },
    "laundering": {
        "methods": ["keywords"],  # keywords | embedding | llm_judge
        "embedding_model": "sentence-transformers/all-MiniLM-L6-v2",
        "embedding_threshold": 0.6,
        "judge": None,  # an llm block (same keys as llm:) for the LLM judge
    },
    "phoenix": {"enabled": False},
}


def deep_merge(base: dict[str, Any], override: dict[str, Any] | None) -> dict[str, Any]:
    """Return a copy of base with the values of override on top (nested dicts are merged)."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def load_settings(path: Path | None = None) -> dict[str, Any]:
    """Read settings.yaml and fill in the defaults."""
    path = path or ROOT / "config" / "settings.yaml"
    with open(path) as f:
        user = yaml.safe_load(f) or {}
    settings = deep_merge(DEFAULTS, user)
    return normalize(settings)


def normalize(settings: dict[str, Any]) -> dict[str, Any]:
    """Apply the old 'guard.enabled' switch to the new 'defense' setting."""
    if settings["guard"].get("enabled") and settings["defense"]["name"] == "none":
        settings["defense"]["name"] = "guard_v0"
    return settings


def load_dotenv(path: Path | None = None) -> None:
    """Read KEY=VALUE lines from .env into os.environ. Existing variables win."""
    path = path or ROOT / ".env"
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip('"').strip("'")
        if key and value and key not in os.environ:
            os.environ[key] = value
