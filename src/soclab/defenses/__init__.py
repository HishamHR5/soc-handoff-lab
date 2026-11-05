"""Defenses. Select one with defense.name in the settings.

  none         no defense
  guard_v0     Phase I guard: fixed patterns + unknown log IDs (guard.py)
  llm_tagging  Lee & Tiwari (2024)
  layered      Karanjai et al. (2026) style: sanitization + delimiters + instruction defense
  guard_v1     the thesis method: typed handoff, provenance, detector, claim-to-evidence, quarantine
  g_safeguard  stub (not implemented)
  paul_nandy   stub (not implemented)
"""

from __future__ import annotations

from .base import Defense, HandoffContext, HandoffDecision
from .guard_v1 import GuardV1
from .simple import GuardV0, Layered, LLMTagging, NoDefense
from .stubs import GSafeguard, PaulNandy

DEFENSES: dict[str, type[Defense]] = {
    "none": NoDefense,
    "guard_v0": GuardV0,
    "llm_tagging": LLMTagging,
    "layered": Layered,
    "guard_v1": GuardV1,
    "g_safeguard": GSafeguard,
    "paul_nandy": PaulNandy,
}


def make_defense(name: str, seed: int = 0) -> Defense:
    if name not in DEFENSES:
        raise ValueError(f"unknown defense {name!r}; use one of {sorted(DEFENSES)}")
    if name == "layered":
        return Layered(seed)
    return DEFENSES[name]()


__all__ = ["Defense", "HandoffContext", "HandoffDecision", "DEFENSES", "make_defense"]
