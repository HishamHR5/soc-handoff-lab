"""Tests for llm.py: backends (through the local mock server), retries, cache, rate limit."""

from __future__ import annotations

import socket

import pytest

from soclab.config import load_dotenv
from soclab.llm import (
    LLM,
    LLMConfigError,
    LLMError,
    LLMResponse,
    MeteredLLM,
    RateLimiter,
    ResponseCache,
    RetryableError,
    UsageMeter,
    make_backend,
    make_llm,
    strip_think,
)
from soclab.prompts import TRIAGE

USER = "ALERT A-1: test (source IP 1.2.3.4)\nLOGS:\n[log-0001] Invalid user root from 1.2.3.4 port 22"


def cfg(server_url: str, backend: str, **extra) -> dict:
    return {"backend": backend, "model": "mock-model", "base_url": server_url, "max_retries": 3,
            "backoff_base_s": 0.0, "timeout_s": 5, **extra}


@pytest.mark.parametrize("backend,base,env", [
    ("openai_compat", "/v1", None),
    ("openai", "/v1", "OPENAI_API_KEY"),
    ("anthropic", "", "ANTHROPIC_API_KEY"),
    ("gemini", "", "GEMINI_API_KEY"),
])
def test_backends_against_mock_server(mock_server, monkeypatch, backend, base, env):
    if env:
        monkeypatch.setenv(env, "test-key-123")
    llm = make_llm(cfg(mock_server.url + base, backend, temperature=0.2, seed=5,
                       price_in_per_mtok=1.0, price_out_per_mtok=2.0))
    r = llm.chat(TRIAGE, USER)
    assert r.text.startswith("Triage:")
    assert r.tokens_in > 0 and r.tokens_out > 0
    assert r.cost_usd == pytest.approx((r.tokens_in * 1 + r.tokens_out * 2) / 1e6)
    assert llm.host == "127.0.0.1"
    body = mock_server.requests[-1]["body"]
    headers = {k.lower(): v for k, v in mock_server.requests[-1]["headers"].items()}
    if backend == "anthropic":
        assert "temperature" not in body           # API version 2026-10-21 rejects it
        assert body["system"] == TRIAGE
        assert headers["authorization"] == "Bearer test-key-123"  # anthropic SDK 2.x
        assert headers["anthropic-version"] == "2026-10-21"
    elif backend == "gemini":
        assert body["generationConfig"] == {"maxOutputTokens": 1024, "temperature": 0.2, "seed": 5}
        assert headers["x-goog-api-key"] == "test-key-123"
    else:
        assert body["temperature"] == 0.2 and body["seed"] == 5
        assert ("max_completion_tokens" in body) == (backend == "openai")


def test_anthropic_effort_is_sent(mock_server, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    make_llm(cfg(mock_server.url, "anthropic", effort="low")).chat(TRIAGE, USER)
    assert mock_server.requests[-1]["body"]["output_config"] == {"effort": "low"}


@pytest.mark.parametrize("backend,base,env", [
    ("openai_compat", "/v1", None), ("anthropic", "", "ANTHROPIC_API_KEY"), ("gemini", "", "GEMINI_API_KEY"),
])
def test_retry_on_429_and_5xx(mock_server, monkeypatch, backend, base, env):
    if env:
        monkeypatch.setenv(env, "k")
    mock_server.fail_next = [429, 500, 503]
    sleeps: list[float] = []
    llm = make_llm(cfg(mock_server.url + base, backend))
    llm._sleep = sleeps.append
    assert llm.chat(TRIAGE, USER).text.startswith("Triage:")
    assert len(mock_server.requests) == 4 and len(sleeps) == 3
    assert sleeps[0] == 0.0  # the 429 had "retry-after: 0"


def test_gives_up_after_max_retries(mock_server):
    mock_server.fail_next = [500] * 10
    llm = make_llm(cfg(mock_server.url + "/v1", "openai_compat", max_retries=2))
    llm._sleep = lambda s: None
    with pytest.raises(LLMError, match="failed after 3 attempts"):
        llm.chat(TRIAGE, USER)


@pytest.mark.parametrize("backend,base,env", [
    ("openai_compat", "/v1", None), ("anthropic", "", "ANTHROPIC_API_KEY"), ("gemini", "", "GEMINI_API_KEY"),
])
def test_no_retry_on_400(mock_server, monkeypatch, backend, base, env):
    if env:
        monkeypatch.setenv(env, "k")
    mock_server.fail_next = [400]
    with pytest.raises(LLMError) as err:
        make_llm(cfg(mock_server.url + base, backend)).chat(TRIAGE, USER)
    assert not isinstance(err.value, RetryableError)
    assert len(mock_server.requests) == 1


@pytest.mark.parametrize("backend", ["openai_compat", "anthropic", "gemini"])
def test_connection_error_is_retried(monkeypatch, backend):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    monkeypatch.setenv("GEMINI_API_KEY", "k")
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens on this port now
    llm = make_llm(cfg(f"http://127.0.0.1:{port}", backend, max_retries=1, timeout_s=1))
    llm._sleep = lambda s: None
    with pytest.raises(LLMError, match="failed after 2 attempts"):
        llm.chat("s", "u")


@pytest.mark.parametrize("backend,var", [("openai", "OPENAI_API_KEY"), ("anthropic", "ANTHROPIC_API_KEY"),
                                         ("gemini", "GEMINI_API_KEY")])
def test_missing_key_gives_clear_error(backend, var):
    with pytest.raises(LLMConfigError, match=f"{var}.*\\.env"):
        make_backend({"backend": backend, "model": "m"})


def test_unknown_backend():
    with pytest.raises(LLMConfigError, match="Unknown llm.backend"):
        make_backend({"backend": "nope", "model": "m"})


def test_aliases_map_to_openai_compat(mock_server):
    llm = make_llm({"backend": "ollama", "model": "x", "base_url": mock_server.url + "/v1"})
    assert llm.backend.name == "openai_compat"


def test_strip_think():
    assert strip_think("<think>secret plan</think>\nVERDICT: TP") == "VERDICT: TP"
    assert strip_think("answer <think>unfinished") == "answer"


def test_cache_returns_saved_answer_without_a_call(tmp_path, mock_server):
    c = cfg(mock_server.url + "/v1", "openai_compat", cache={"enabled": True, "dir": str(tmp_path)})
    llm = make_llm(c)
    first = llm.chat(TRIAGE, USER)
    second = llm.chat(TRIAGE, USER)
    assert len(mock_server.requests) == 1
    assert second.cached and not first.cached and second.text == first.text
    llm.with_seed(99).chat(TRIAGE, USER)  # another seed = another key
    assert len(mock_server.requests) == 2


def test_cache_key_depends_on_all_parts():
    base = dict(backend="b", model="m", system="s", user="u", temperature=0.0, seed=1, max_tokens=5)
    keys = {ResponseCache.key(**base)}
    for k, v in [("model", "m2"), ("system", "s2"), ("user", "u2"), ("temperature", 0.7), ("seed", 2)]:
        keys.add(ResponseCache.key(**{**base, k: v}))
    assert len(keys) == 6


def test_rate_limiter_spaces_calls():
    now = [0.0]
    slept: list[float] = []
    rl = RateLimiter(60, clock=lambda: now[0], sleep=slept.append)  # 1 call per second
    rl.wait()
    rl.wait()
    rl.wait()
    assert slept == [1.0, 2.0]
    RateLimiter(0).wait()  # no limit: returns at once


def test_meter_sums_usage():
    meter = UsageMeter()
    meter.add(LLMResponse("a", "m", 10, 5, 0.5, 0.01))
    meter.add(LLMResponse("b", "m", 1, 1, 0.25, 0.02, cached=True))
    got = meter.take()
    assert got == {"llm_calls": 2, "tokens_in": 11, "tokens_out": 6, "latency_s": 0.75,
                   "cost_usd": 0.03, "cached_calls": 1}
    assert meter.take()["llm_calls"] == 0
    meter.add(LLMResponse("c", "m"))
    assert meter.take()["cost_usd"] is None


def test_metered_llm_and_fake_backend():
    meter = UsageMeter()
    llm = MeteredLLM(make_llm({"backend": "fake"}), meter)
    assert llm.model == "fake-gullible"
    assert llm.chat(TRIAGE, USER).text.startswith("Triage")
    assert meter.take()["llm_calls"] == 1


def test_llm_never_sends_temperature_for_anthropic():
    class B:
        name, model, base_url = "anthropic", "m", "https://x"
    assert LLM(B(), {"temperature": 0.5}).temperature is None  # type: ignore[arg-type]


def test_load_dotenv(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nSOCLAB_T1=abc\nSOCLAB_T2='q'\nEMPTY=\nbad line\n")
    monkeypatch.setenv("SOCLAB_T2", "keep")
    monkeypatch.delenv("SOCLAB_T1", raising=False)
    load_dotenv(env)
    import os
    assert os.environ["SOCLAB_T1"] == "abc" and os.environ["SOCLAB_T2"] == "keep"
    monkeypatch.delenv("SOCLAB_T1")
    load_dotenv(tmp_path / "missing.env")  # no error


def test_network_guard_blocks_internet():
    from conftest import NetworkBlocked
    with pytest.raises(NetworkBlocked):
        socket.create_connection(("example.com", 80), timeout=1)
