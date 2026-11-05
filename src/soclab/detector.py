"""Injection detector: finds instruction-like text that is aimed at an AI agent.

Used by guard_v1 (detection) and by the layered defense (sanitization).
guard_v0 keeps its own, older pattern list (guard.py), so the baseline does not change.

It also looks inside base64 values and URL encoding (one level), because payloads can
be encoded.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

PATTERNS: dict[str, str] = {
    "role_spoof": r"\b(?:SYSTEM|ADMIN|ASSISTANT|DEVELOPER)\s*:|<\|?(?:system|im_start)\|?>|\[/?INST\]",
    "override": r"\b(?:ignore|disregard|forget)\b.{0,20}\b(?:previous|prior|above|earlier|all)\b.{0,20}"
                r"\b(?:instructions|rules|text|prompts?)\b",
    "do_not_flag": r"\b(?:do not|don't|never|please do not)\s+(?:flag|alert|escalate|report|mention)\b",
    "mark_as": r"\bmark\b.{0,30}\bas\b.{0,25}\b(?:true positive|false positive|benign|critical|routine)\b",
    "treat_as": r"\b(?:summari[sz]e|classify|treat|label|close)\b.{0,50}\bas\b.{0,30}"
                r"\b(?:routine|benign|harmless|approved|authori[sz]ed|false positive|true positive)\b",
    "add_to_report": r"\b(?:add|include|insert|write|copy|put)\b.{0,40}\b(?:to|in|into)\s+(?:the|your)\s+report\b",
    "exfil": r"\b(?:copy|reveal|print|repeat|include|output|show|share)\b.{0,50}"
             r"\b(?:system (?:prompt|instructions|message)|internal id|hidden instructions|api key|secret)\b",
}
COMPILED = {name: re.compile(p, re.I) for name, p in PATTERNS.items()}
B64_RE = re.compile(r"(?:b64:)?([A-Za-z0-9+/]{24,}={0,2})")


@dataclass(frozen=True)
class Hit:
    name: str
    start: int
    end: int
    encoded: bool = False  # True: found after decoding base64 / URL encoding


def _decode_b64(value: str) -> str | None:
    try:
        text = base64.b64decode(value, validate=True).decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return None
    return text if text.isprintable() else None


def detect(text: str) -> list[Hit]:
    """All hits in the text, in text order."""
    hits = [Hit(name, m.start(), m.end()) for name, rx in COMPILED.items() for m in rx.finditer(text)]
    for m in B64_RE.finditer(text):
        decoded = _decode_b64(m.group(1))
        if decoded and any(rx.search(decoded) for rx in COMPILED.values()):
            hits.append(Hit("encoded_instruction", m.start(), m.end(), encoded=True))
    if "%" in text or "+" in text:
        unquoted = unquote_plus(text)
        if unquoted != text and not hits:
            for name, rx in COMPILED.items():
                if rx.search(unquoted):
                    hits.append(Hit(name, 0, len(text), encoded=True))
                    break
    return sorted(hits, key=lambda h: (h.start, h.end))


def sanitize(text: str, replacement: str = "[removed]") -> tuple[str, list[Hit]]:
    """Replace each hit with [removed]. URL-encoded hits are replaced in decoded form."""
    hits = detect(text)
    if not hits:
        return text, []
    if any(h.encoded and h.name != "encoded_instruction" for h in hits):
        decoded_text, _ = sanitize(unquote_plus(text), replacement)
        return decoded_text, hits
    out, last = [], 0
    for h in hits:
        if h.start < last:  # overlapping hit: already removed
            continue
        out.append(text[last:h.start])
        out.append(replacement)
        last = h.end
    out.append(text[last:])
    return "".join(out), hits
