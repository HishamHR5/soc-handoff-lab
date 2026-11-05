"""One interface for all models:  llm.chat(system, user) -> LLMResponse

Backends (select with llm.backend in config/settings.yaml):
  fake          scripted model, no network (see fake_llm.py). For tests only.
  openai_compat Ollama, vLLM, LM Studio (OpenAI-compatible HTTP API). Aliases: ollama, vllm.
  openai        OpenAI API.
  anthropic     Claude API (official SDK). It never sends temperature (API version 2026-10-21).
  gemini        Google Gemini API (REST).

The LLM class adds the same things to every backend:
  - a rate limit (requests per minute), shared by all threads,
  - retries with exponential backoff for 429, 5xx, timeouts and connection errors,
  - an optional on-disk cache (key = hash of backend, model, prompts, temperature, seed, max_tokens),
  - removal of <think>...</think> blocks,
  - token counts, latency and cost in each LLMResponse.

A backend connects ONLY to its own base_url. No other network access happens here.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import re
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import urlparse

import httpx

THINK_RE = re.compile(r"<think>.*?(</think>|$)", flags=re.S)


@dataclass(frozen=True)
class LLMResponse:
    text: str
    model: str
    tokens_in: int = 0
    tokens_out: int = 0
    latency_s: float = 0.0
    cost_usd: float | None = None
    cached: bool = False
    backend: str = ""


@dataclass(frozen=True)
class Completion:
    """What a backend returns (before the LLM class adds latency, cost and cleanup)."""

    text: str
    tokens_in: int = 0
    tokens_out: int = 0
    model: str = ""


class LLMError(RuntimeError):
    """The call failed and a retry will not help (for example 400 or 401)."""


class LLMConfigError(LLMError):
    """Bad settings, for example a missing API key."""


class RetryableError(LLMError):
    """The call failed, but a retry can help (429, 5xx, timeout, connection error)."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class Backend(Protocol):
    name: str
    model: str
    base_url: str

    def complete(
        self, system: str, user: str, *, temperature: float | None, max_tokens: int, seed: int | None
    ) -> Completion: ...


# --------------------------------------------------------------------------- helpers


def strip_think(text: str) -> str:
    """Remove hidden reasoning in <think> tags (also an unclosed tag at the end)."""
    return THINK_RE.sub("", text).strip()


def _retry_after(headers: Any) -> float | None:
    try:
        value = headers.get("retry-after") if headers is not None else None
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def require_key(env_var: str, backend: str) -> str:
    key = os.environ.get(env_var, "").strip()
    if not key:
        raise LLMConfigError(
            f"The '{backend}' backend needs the environment variable {env_var}. "
            f"Copy .env.example to .env and set {env_var}=<your key>. Do not put keys in settings.yaml."
        )
    return key


class RateLimiter:
    """Allow at most `per_minute` calls per minute, evenly spaced. Thread-safe."""

    def __init__(self, per_minute: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Callable[[float], None] = time.sleep):
        self.interval = 60.0 / per_minute if per_minute and per_minute > 0 else 0.0
        self._next = 0.0
        self._lock = threading.Lock()
        self._clock, self._sleep = clock, sleep

    def wait(self) -> None:
        if not self.interval:
            return
        with self._lock:
            now = self._clock()
            start = max(now, self._next)
            self._next = start + self.interval
        if start > now:
            self._sleep(start - now)


class ResponseCache:
    """One JSON file per answer: <dir>/<key[:2]>/<key>.json. Writes are atomic."""

    def __init__(self, directory: Path | str):
        self.dir = Path(directory)

    @staticmethod
    def key(**parts: Any) -> str:
        blob = json.dumps(parts, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(blob.encode()).hexdigest()

    def _path(self, key: str) -> Path:
        return self.dir / key[:2] / f"{key}.json"

    def get(self, key: str) -> LLMResponse | None:
        path = self._path(key)
        if not path.exists():
            return None
        return LLMResponse(**{**json.loads(path.read_text()), "cached": True})

    def put(self, key: str, response: LLMResponse) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(f".{threading.get_ident()}.tmp")
        tmp.write_text(json.dumps(asdict(response)))
        os.replace(tmp, path)


# --------------------------------------------------------------------------- backends


class OpenAICompatBackend:
    """OpenAI chat completions API: openai_compat (Ollama, vLLM, LM Studio) and openai."""

    def __init__(self, name: str, model: str, base_url: str, api_key: str, timeout_s: float):
        from openai import OpenAI

        self.name, self.model, self.base_url = name, model, base_url
        # max_retries=0: the LLM class does the retries, the same way for all backends.
        self.client = OpenAI(base_url=base_url, api_key=api_key, max_retries=0, timeout=timeout_s)

    def complete(self, system: str, user: str, *, temperature: float | None, max_tokens: int,
                 seed: int | None) -> Completion:
        import openai

        params: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        # The OpenAI API uses max_completion_tokens. Local servers use max_tokens.
        params["max_completion_tokens" if self.name == "openai" else "max_tokens"] = max_tokens
        if temperature is not None:
            params["temperature"] = temperature
        if seed is not None:
            params["seed"] = seed
        try:
            resp = self.client.chat.completions.create(**params)
        except openai.RateLimitError as e:
            raise RetryableError(f"429 rate limit: {e}", _retry_after(e.response.headers)) from e
        except openai.InternalServerError as e:
            raise RetryableError(f"{e.status_code} server error: {e}", _retry_after(e.response.headers)) from e
        except openai.APIConnectionError as e:  # also covers timeouts
            raise RetryableError(f"connection error: {e}") from e
        except openai.APIStatusError as e:
            raise LLMError(f"{self.name} API error {e.status_code}: {e}") from e
        usage = resp.usage
        return Completion(
            text=resp.choices[0].message.content or "",
            tokens_in=(usage.prompt_tokens or 0) if usage else 0,
            tokens_out=(usage.completion_tokens or 0) if usage else 0,
            model=resp.model or self.model,
        )


class AnthropicBackend:
    """Claude Messages API through the official SDK (anthropic>=2.0, API version 2026-10-21).

    The 2026-10-21 API version rejects temperature/top_p/top_k, so they are never sent.
    """

    def __init__(self, model: str, base_url: str, api_key: str, timeout_s: float,
                 effort: str | None = None):
        import anthropic

        self.name, self.model, self.base_url, self.effort = "anthropic", model, base_url, effort
        # base_url is passed explicitly, so an ANTHROPIC_BASE_URL in the shell is not used.
        self.client = anthropic.Anthropic(api_key=api_key, base_url=base_url, max_retries=0,
                                          timeout=timeout_s)

    def complete(self, system: str, user: str, *, temperature: float | None, max_tokens: int,
                 seed: int | None) -> Completion:
        import anthropic

        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self.effort:
            params["output_config"] = {"effort": self.effort}
        try:
            resp = self.client.messages.create(**params)
        except (anthropic.RateLimitError, anthropic.InternalServerError) as e:
            raise RetryableError(f"{e.status_code} {type(e).__name__}: {e}",
                                 _retry_after(e.response.headers)) from e
        except anthropic.APIConnectionError as e:  # also covers timeouts
            raise RetryableError(f"connection error: {e}") from e
        except anthropic.APIStatusError as e:
            if e.status_code >= 500:  # 529 overloaded, 503, ...
                raise RetryableError(f"{e.status_code} {type(e).__name__}: {e}",
                                     _retry_after(e.response.headers)) from e
            raise LLMError(f"anthropic API error {e.status_code}: {e}") from e
        # A refusal (stop_reason "refusal") has no text. The agent then gets "" and the
        # verdict becomes UNKNOWN, which the metrics count.
        text = "".join(block.text for block in resp.content if block.type == "text")
        return Completion(text=text, tokens_in=resp.usage.input_tokens,
                          tokens_out=resp.usage.output_tokens, model=resp.model)


class GeminiBackend:
    """Google Gemini generateContent REST API. The key goes in a header, not in the URL."""

    def __init__(self, model: str, base_url: str, api_key: str, timeout_s: float):
        self.name, self.model, self.base_url = "gemini", model, base_url.rstrip("/")
        self.client = httpx.Client(timeout=timeout_s, headers={"x-goog-api-key": api_key})

    def complete(self, system: str, user: str, *, temperature: float | None, max_tokens: int,
                 seed: int | None) -> Completion:
        config: dict[str, Any] = {"maxOutputTokens": max_tokens}
        if temperature is not None:
            config["temperature"] = temperature
        if seed is not None:
            config["seed"] = seed
        body = {
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"role": "user", "parts": [{"text": user}]}],
            "generationConfig": config,
        }
        url = f"{self.base_url}/v1beta/models/{self.model}:generateContent"
        try:
            r = self.client.post(url, json=body)
        except httpx.HTTPError as e:  # timeouts and connection errors
            raise RetryableError(f"connection error: {e}") from e
        if r.status_code == 429 or r.status_code >= 500:
            raise RetryableError(f"{r.status_code}: {r.text[:200]}", _retry_after(r.headers))
        if r.status_code != 200:
            raise LLMError(f"gemini API error {r.status_code}: {r.text[:300]}")
        data = r.json()
        candidates = data.get("candidates") or [{}]
        parts = (candidates[0].get("content") or {}).get("parts") or []
        usage = data.get("usageMetadata") or {}
        return Completion(
            text="".join(p.get("text", "") for p in parts if not p.get("thought")),
            tokens_in=usage.get("promptTokenCount", 0),
            tokens_out=usage.get("candidatesTokenCount", 0) + usage.get("thoughtsTokenCount", 0),
            model=data.get("modelVersion", self.model),
        )


BACKEND_DEFAULTS = {
    # backend: (default base_url, default API key variable, key required?)
    "openai_compat": ("http://localhost:11434/v1", "OPENAI_COMPAT_API_KEY", False),
    "openai": ("https://api.openai.com/v1", "OPENAI_API_KEY", True),
    "anthropic": ("https://api.anthropic.com", "ANTHROPIC_API_KEY", True),
    "gemini": ("https://generativelanguage.googleapis.com", "GEMINI_API_KEY", True),
}
ALIASES = {"ollama": "openai_compat", "vllm": "openai_compat", "lmstudio": "openai_compat"}


def make_backend(cfg: dict[str, Any]) -> Backend:
    from .fake_llm import FakeBackend

    name = ALIASES.get(cfg["backend"], cfg["backend"])
    if name == "fake":
        return FakeBackend(cfg.get("model", "fake-gullible"), cfg.get("fake_behavior", "gullible"))
    if name not in BACKEND_DEFAULTS:
        raise LLMConfigError(f"Unknown llm.backend: {cfg['backend']!r}. "
                             f"Use one of: fake, {', '.join(BACKEND_DEFAULTS)}.")
    default_url, default_env, key_required = BACKEND_DEFAULTS[name]
    base_url = cfg.get("base_url") or default_url
    env_var = cfg.get("api_key_env") or default_env
    if key_required:
        key = require_key(env_var, name)
    else:
        key = os.environ.get(env_var, "").strip() or cfg.get("api_key") or "none"
    timeout = float(cfg.get("timeout_s", 60.0))
    if name in ("openai_compat", "openai"):
        return OpenAICompatBackend(name, cfg["model"], base_url, key, timeout)
    if name == "anthropic":
        return AnthropicBackend(cfg["model"], base_url, key, timeout, cfg.get("effort"))
    return GeminiBackend(cfg["model"], base_url, key, timeout)


# --------------------------------------------------------------------------- the client


class LLM:
    """The object that agents use. Thread-safe."""

    def __init__(self, backend: Backend, cfg: dict[str, Any], *,
                 sleep: Callable[[float], None] = time.sleep):
        self.backend = backend
        self.cfg = cfg
        self.temperature: float | None = None if backend.name == "anthropic" else cfg.get("temperature")
        self.max_tokens = int(cfg.get("max_tokens", 1024))
        self.seed: int | None = cfg.get("seed")
        self.max_retries = int(cfg.get("max_retries", 5))
        self.backoff_base = float(cfg.get("backoff_base_s", 1.0))
        self.backoff_max = float(cfg.get("backoff_max_s", 60.0))
        self.price_in = cfg.get("price_in_per_mtok")
        self.price_out = cfg.get("price_out_per_mtok")
        self.limiter = RateLimiter(cfg.get("requests_per_minute", 0) or 0, sleep=sleep)
        cache_cfg = cfg.get("cache") or {}
        self.cache = ResponseCache(cache_cfg["dir"]) if cache_cfg.get("enabled") else None
        self._sleep = sleep

    @property
    def model(self) -> str:
        return self.backend.model

    @property
    def host(self) -> str:
        """The only network host that this client connects to ("" for the fake backend)."""
        return urlparse(self.backend.base_url).hostname or ""

    def with_seed(self, seed: int | None) -> LLM:
        """A copy that sends another seed (it shares the rate limit and the cache)."""
        clone = object.__new__(LLM)
        clone.__dict__.update(self.__dict__)
        clone.seed = seed
        return clone

    def cost(self, tokens_in: int, tokens_out: int) -> float | None:
        if self.price_in is None or self.price_out is None:
            return None
        return (tokens_in * self.price_in + tokens_out * self.price_out) / 1_000_000

    def chat(self, system: str, user: str) -> LLMResponse:
        key = ""
        if self.cache:
            key = ResponseCache.key(backend=self.backend.name, model=self.model, system=system,
                                    user=user, temperature=self.temperature, seed=self.seed,
                                    max_tokens=self.max_tokens)
            hit = self.cache.get(key)
            if hit:
                return hit
        start = time.monotonic()
        completion = self._call_with_retries(system, user)
        response = LLMResponse(
            text=strip_think(completion.text),
            model=completion.model or self.model,
            tokens_in=completion.tokens_in,
            tokens_out=completion.tokens_out,
            latency_s=round(time.monotonic() - start, 4),
            cost_usd=self.cost(completion.tokens_in, completion.tokens_out),
            backend=self.backend.name,
        )
        if self.cache:
            self.cache.put(key, response)
        return response

    def _call_with_retries(self, system: str, user: str) -> Completion:
        for attempt in range(self.max_retries + 1):
            self.limiter.wait()
            try:
                return self.backend.complete(system, user, temperature=self.temperature,
                                             max_tokens=self.max_tokens, seed=self.seed)
            except RetryableError as e:
                if attempt == self.max_retries:
                    raise LLMError(f"{self.backend.name}: failed after {attempt + 1} attempts: {e}") from e
                delay = e.retry_after if e.retry_after is not None else (
                    self.backoff_base * 2**attempt + random.uniform(0, self.backoff_base))
                self._sleep(min(delay, self.backoff_max))
        raise AssertionError("unreachable")  # pragma: no cover


class MeteredLLM:
    """Wraps an LLM for ONE run. It adds each call's usage to a meter that the tracer reads."""

    def __init__(self, llm: LLM, meter: UsageMeter):
        self.llm, self.meter = llm, meter

    @property
    def model(self) -> str:
        return self.llm.model

    def chat(self, system: str, user: str) -> LLMResponse:
        response = self.llm.chat(system, user)
        self.meter.add(response)
        return response


class UsageMeter:
    """Collects LLM usage since the last take(). The tracer adds it to the next event."""

    def __init__(self) -> None:
        self._pending: list[LLMResponse] = []

    def add(self, response: LLMResponse) -> None:
        self._pending.append(response)

    def take(self) -> dict[str, Any]:
        calls, self._pending = self._pending, []
        costs = [c.cost_usd for c in calls]
        return {
            "llm_calls": len(calls),
            "tokens_in": sum(c.tokens_in for c in calls),
            "tokens_out": sum(c.tokens_out for c in calls),
            "latency_s": round(sum(c.latency_s for c in calls), 4),
            "cost_usd": None if any(c is None for c in costs) else round(sum(costs), 8),  # type: ignore[arg-type]
            "cached_calls": sum(c.cached for c in calls),
        }


def make_llm(cfg: dict[str, Any]) -> LLM:
    """Build the LLM client from the llm: block of the settings."""
    from .config import DEFAULTS, deep_merge

    full = deep_merge(DEFAULTS["llm"], cfg)
    return LLM(make_backend(full), full)


__all__ = ["LLM", "LLMResponse", "LLMError", "LLMConfigError", "RetryableError", "MeteredLLM",
           "UsageMeter", "RateLimiter", "ResponseCache", "make_llm", "make_backend", "strip_think"]
