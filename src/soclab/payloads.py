"""Payload generator: put attacker text into a field that the attacker controls.

Fields (see fields.py):
  auth.log         -> ssh_username
  access.log       -> user_agent (default), url_path, query_string, referer
  apache_error.log -> url_path

Values in url_path and query_string are URL-encoded (spaces cannot be in a request line).
Values in quoted fields lose their double quotes (they would break the log format).
"""

from __future__ import annotations

import base64
import random
import string
from pathlib import Path
from typing import Any
from urllib.parse import quote, quote_plus

import yaml

from .fields import ATTACKER_FIELDS, access_request_end, field_spans

TEMPLATES_FILE = Path(__file__).resolve().parents[2] / "payloads" / "templates.yaml"
GOALS = ["CONCEAL", "FABRICATE", "EXFIL", "INSTRUCT"]
VARIANTS = ["direct", "polite", "hidden", "split", "encoded"]


def load_templates(path: Path | None = None) -> dict[str, Any]:
    with open(path or TEMPLATES_FILE) as f:
        data: dict[str, Any] = yaml.safe_load(f)
    return data


def new_marker(rng: random.Random) -> str:
    """A unique code like 'ZX4K9Q2T'. It must not appear in normal logs."""
    return "ZX" + "".join(rng.choices(string.ascii_uppercase + string.digits, k=6))


def render(template: dict[str, Any], variant: str, marker: str) -> list[str]:
    """The text(s) to inject: 1 part, or 2 parts for the 'split' variant."""
    if variant not in VARIANTS:
        raise ValueError(f"unknown payload variant {variant!r}; use one of {VARIANTS}")
    value = template.get("variants", {}).get(variant, template["text"])
    parts = value if isinstance(value, list) else [value]
    parts = [p.format(marker=marker) for p in parts]
    if variant == "encoded":
        parts = ["b64:" + base64.b64encode(p.encode()).decode() for p in parts]
    return parts


CUSTOM_MAX_CHARS = 300


def custom_template(template: dict[str, Any], text: str) -> dict[str, Any]:
    """A goal template with the user's own payload text (Propagation Viewer).

    The text becomes one line (a log line cannot have line breaks). "{marker}" marks where
    the unique tracking code goes; if it is missing, " (ref {marker})" is added at the end,
    because the tracer needs the marker. Other braces are kept as text.
    """
    text = " ".join(text.split())[:CUSTOM_MAX_CHARS]
    if not text:
        raise ValueError("the custom payload text is empty")
    if "{marker}" not in text:
        text += " (ref {marker})"
    safe = text.replace("{", "{{").replace("}", "}}").replace("{{marker}}", "{marker}")
    return {**template, "text": safe, "variants": {}}


def plain_text(template: dict[str, Any], variant: str, marker: str) -> str:
    """The readable payload (not encoded). The laundering detectors compare against it."""
    value = template.get("variants", {}).get(variant, template["text"])
    parts = value if isinstance(value, list) else [value]
    return " ".join(p.format(marker=marker) for p in parts)


def encode_for_field(value: str, field: str) -> str:
    if field == "url_path":
        return "/" + quote(value, safe="")
    if field == "query_string":
        return "q=" + quote_plus(value)
    return value.replace('"', "'")


def default_field(source: str) -> str | None:
    fields = ATTACKER_FIELDS.get(source)
    return fields[0] if fields else None


def inject(raw: str, source: str, payload: str, field: str | None = None) -> str | None:
    """Return the log line with the payload in the attacker field, or None if not possible."""
    field = field or default_field(source)
    if field is None or field not in ATTACKER_FIELDS.get(source, []):
        return None
    value = encode_for_field(payload, field)
    for span in field_spans(raw, source):
        if span.field == field:
            return raw[:span.start] + value + raw[span.end:]
    if field == "query_string":  # the line has no query string: add one after the path
        end = access_request_end(raw)
        if end is not None:
            return raw[:end] + "?" + value + raw[end:]
    return None
