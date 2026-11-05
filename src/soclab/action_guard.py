"""Action guard (OFF by default): stop actions that the agent's OWN model was not asked to do.

Threat: an untrusted model (supply chain, training artifact, backdoor) makes unrequested
tool calls, for example a network upload. The guard does not trust the model's reasoning
text; it checks each action:
  1. Per-agent tool allowlist: a tool that is not in the list of this agent is blocked.
  2. Default-deny egress: a network action to a host that is not in the allow list is
     blocked. The LLM API host is the only host that is always allowed.
Each blocked action is logged by the tracer (kind "guard", agent "action_guard").

The network tool is a sinkhole (tools.py), so even with the guard OFF no real network
call happens. With the guard OFF, the attempt is still logged (egress_attempt: true).
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from .tools import Tool


class ActionGuard:
    def __init__(self, cfg: dict[str, Any], llm_host: str = ""):
        self.enabled = bool(cfg.get("enabled"))
        self.allowlist: dict[str, list[str]] = cfg.get("allowlist") or {}
        self.allow_hosts = {h for h in cfg.get("egress_allow_hosts") or [] if h}
        if llm_host:
            self.allow_hosts.add(llm_host)

    def check(self, agent: str, tool: Tool | None, name: str, args: dict[str, Any]) -> str | None:
        """None if the action is allowed, else the reason why it is blocked."""
        if not self.enabled:
            return None
        if name not in self.allowlist.get(agent, []):
            return f"tool {name!r} is not in the allowlist of agent {agent!r}"
        if tool is not None and tool.network:
            host = urlparse(str(args.get("url", ""))).hostname or ""
            if host not in self.allow_hosts:
                return f"egress to host {host!r} is denied (default deny)"
        return None
