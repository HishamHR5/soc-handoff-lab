"""A local mock LLM server for tests. It listens on 127.0.0.1 only.

It speaks 3 HTTP APIs and answers with the fake model (fake_llm.py):
  POST /v1/chat/completions                    OpenAI-compatible (openai, openai_compat)
  POST /v1/messages                            Anthropic Messages API
  POST /v1beta/models/<model>:generateContent  Gemini API

With it, the real-API code path (HTTP client, JSON format, retries) runs without a key
and without internet. Fault injection: put HTTP status codes in `server.fail_next`
(for example [429, 500]); the next requests get these errors first.

  python scripts/mock_llm_server.py --port 8765
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from .fake_llm import FakeBackend


class MockLLMServer:
    def __init__(self, port: int = 0, behavior: str = "gullible"):
        self.fake = FakeBackend("mock-model", behavior)
        self.fail_next: list[int] = []
        self.requests: list[dict[str, Any]] = []  # path, headers, body of each request
        self._lock = threading.Lock()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", port), self._handler_class())
        self.port = self.httpd.server_address[1]
        self._thread: threading.Thread | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> MockLLMServer:
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()

    def __enter__(self) -> MockLLMServer:
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # ------------------------------------------------------------------ request handling
    def handle(self, path: str, headers: dict[str, str], body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        with self._lock:
            self.requests.append({"path": path, "headers": headers, "body": body})
            fail = self.fail_next.pop(0) if self.fail_next else None
        if fail:
            return fail, {"error": {"type": "mock_error", "message": f"injected HTTP {fail}"}}
        if path.endswith("/chat/completions"):
            return 200, self._openai(body)
        if path.endswith("/messages"):
            return 200, self._anthropic(body)
        if ":generateContent" in path:
            return 200, self._gemini(path, body)
        return 404, {"error": {"message": f"unknown path {path}"}}

    def _openai(self, body: dict[str, Any]) -> dict[str, Any]:
        msgs = {m["role"]: m["content"] for m in body["messages"]}
        c = self.fake.complete(msgs.get("system", ""), msgs.get("user", ""))
        return {
            "id": "chatcmpl-mock", "object": "chat.completion", "created": int(time.time()),
            "model": body.get("model", "mock-model"),
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": c.text}}],
            "usage": {"prompt_tokens": c.tokens_in, "completion_tokens": c.tokens_out,
                      "total_tokens": c.tokens_in + c.tokens_out},
        }

    def _anthropic(self, body: dict[str, Any]) -> dict[str, Any]:
        user = body["messages"][-1]["content"]
        c = self.fake.complete(body.get("system", ""), user if isinstance(user, str) else "")
        return {
            "id": "msg_mock", "type": "message", "role": "assistant",
            "model": body.get("model", "mock-model"),
            "content": [{"type": "text", "text": c.text}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": c.tokens_in, "output_tokens": c.tokens_out},
        }

    def _gemini(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        system = body.get("systemInstruction", {}).get("parts", [{}])[0].get("text", "")
        user = body["contents"][-1]["parts"][0]["text"]
        c = self.fake.complete(system, user)
        return {
            "candidates": [{"content": {"role": "model", "parts": [{"text": c.text}]},
                            "finishReason": "STOP"}],
            "usageMetadata": {"promptTokenCount": c.tokens_in, "candidatesTokenCount": c.tokens_out},
            "modelVersion": path.split("/models/")[1].split(":")[0],
        }

    def _handler_class(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 (name from http.server)
                length = int(self.headers.get("Content-Length", 0))
                body = json.loads(self.rfile.read(length) or b"{}")
                status, payload = server.handle(self.path, dict(self.headers), body)
                data = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                if status == 429:
                    self.send_header("retry-after", "0")
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: Any) -> None:  # keep test output clean
                return

        return Handler
