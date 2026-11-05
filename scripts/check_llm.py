"""Send ONE test prompt to the configured LLM backend and print the result.

  python scripts/check_llm.py                                  # backend from config/settings.yaml
  python scripts/check_llm.py --backend anthropic --model claude-haiku-5-5
  python scripts/check_llm.py --backend ollama --model qwen2.5:0.5b

The API key comes from .env (see .env.example). Exit code 0 = the call worked.
"""

from __future__ import annotations

import argparse
import sys

from soclab.config import load_dotenv, load_settings
from soclab.llm import LLMError, make_llm

SYSTEM = "You are a test agent. Answer with one short sentence."
USER = "Say: the SOC handoff lab can reach this model."


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--backend")
    ap.add_argument("--model")
    ap.add_argument("--base-url")
    a = ap.parse_args()

    load_dotenv()
    cfg = load_settings()["llm"]
    for key, value in (("backend", a.backend), ("model", a.model), ("base_url", a.base_url)):
        if value:
            cfg[key] = value
    cfg["cache"] = {"enabled": False}
    try:
        llm = make_llm(cfg)
        r = llm.chat(SYSTEM, USER)
    except LLMError as e:
        print(f"FAILED ({cfg['backend']} / {cfg['model']}): {e}")
        return 1
    print(f"backend : {r.backend}\nmodel   : {r.model}\nhost    : {llm.host or '(none, no network)'}")
    print(f"tokens  : in={r.tokens_in} out={r.tokens_out}\nlatency : {r.latency_s:.2f} s")
    print(f"cost    : {'unknown (set price_in/out_per_mtok)' if r.cost_usd is None else f'{r.cost_usd:.6f} USD'}")
    print(f"answer  : {r.text!r}")
    return 0 if r.text.strip() else 1


if __name__ == "__main__":
    sys.exit(main())
