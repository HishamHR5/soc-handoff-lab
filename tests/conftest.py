"""Shared test setup.

No test may use the internet. This file makes every connection to a host that is not
the local machine fail. If a test (or the code under test) tries it, the test fails.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

LOCAL = {"127.0.0.1", "::1", "localhost"}
_real_connect = socket.socket.connect
_real_getaddrinfo = socket.getaddrinfo


class NetworkBlocked(RuntimeError):
    pass


def _host(address: object) -> str:
    return str(address[0]) if isinstance(address, tuple) else str(address)


def _guarded_connect(self: socket.socket, address: object) -> None:
    if self.family in (socket.AF_INET, socket.AF_INET6) and _host(address) not in LOCAL:
        raise NetworkBlocked(f"test tried to connect to {address!r}")
    return _real_connect(self, address)  # type: ignore[arg-type]


def _guarded_getaddrinfo(host, *args, **kwargs):  # type: ignore[no-untyped-def]
    if host is not None and str(host) not in LOCAL:
        raise NetworkBlocked(f"test tried to resolve {host!r}")
    return _real_getaddrinfo(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def no_internet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)


@pytest.fixture(autouse=True)
def no_real_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests never see the real API keys of the person who runs them."""
    for var in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY", "OPENAI_COMPAT_API_KEY",
                "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL"):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def mock_server():
    from soclab.mock_server import MockLLMServer

    with MockLLMServer() as server:
        yield server


@pytest.fixture
def tmp_root(tmp_path: Path) -> Path:
    return tmp_path
