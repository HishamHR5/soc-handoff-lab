"""Start the local mock LLM server (OpenAI, Anthropic and Gemini formats) on 127.0.0.1.

  python scripts/mock_llm_server.py --port 8765

Then run an experiment against it (this tests the real HTTP code path with no key):
  python scripts/run_experiment.py experiments/smoke_mock.yaml
"""

from __future__ import annotations

import argparse
import time

from soclab.mock_server import MockLLMServer


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--behavior", choices=["gullible", "rogue"], default="gullible")
    a = ap.parse_args()
    with MockLLMServer(a.port, a.behavior) as server:
        print(f"Mock LLM server on {server.url}  (OpenAI base_url: {server.url}/v1). Ctrl+C stops it.", flush=True)
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            print(f"\nStopped. {len(server.requests)} requests served.")


if __name__ == "__main__":
    main()
