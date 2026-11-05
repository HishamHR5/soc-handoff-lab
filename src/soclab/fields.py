"""Find the attacker-controlled fields in a log line.

An attacker can choose the text of these fields:
  auth.log          ssh_username                       (sshd "Invalid user <X> from ...")
  access.log        url_path, query_string, referer, user_agent   (Apache combined format)
  apache_error.log  url_path                           ("File does not exist: <X>")

The payload generator writes into these fields. Guard v1 uses the same spans to put
provenance labels around untrusted text.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

ATTACKER_FIELDS = {
    "auth.log": ["ssh_username"],
    "access.log": ["user_agent", "url_path", "query_string", "referer"],
    "apache_error.log": ["url_path"],
}

SSH_USER_RES = [
    re.compile(r"[Ii]nvalid user (?P<v>.*?) from \d"),
    re.compile(r"(?:Failed|Accepted) \w+ for (?P<v>.*?) from \d"),
]
ACCESS_RE = re.compile(
    r'(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<url_path>[^?\s"]*)(?:\?(?P<query_string>[^\s"]*))?(?: (?P<proto>[^"]*))?" '
    r'(?P<status>\d{3}) (?P<size>\S+)(?: "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)
APACHE_ERROR_RE = re.compile(
    r"(?:File does not exist|Directory index forbidden by rule|script not found or unable to stat"
    r"|client denied by server configuration): (?P<url_path>\S+)"
)


@dataclass(frozen=True)
class Span:
    field: str
    start: int
    end: int


def field_spans(raw: str, source: str) -> list[Span]:
    """All attacker-controlled fields of one log line, in text order."""
    spans: list[Span] = []
    if source == "auth.log":
        for regex in SSH_USER_RES:
            m = regex.search(raw)
            if m:
                spans.append(Span("ssh_username", m.start("v"), m.end("v")))
                break
    elif source == "access.log":
        m = ACCESS_RE.search(raw)
        if m:
            for name in ("url_path", "query_string", "referer", "user_agent"):
                if m.group(name) is not None:
                    spans.append(Span(name, m.start(name), m.end(name)))
    elif source == "apache_error.log":
        m = APACHE_ERROR_RE.search(raw)
        if m:
            spans.append(Span("url_path", m.start("url_path"), m.end("url_path")))
    return sorted(spans, key=lambda s: s.start)


def access_request_end(raw: str) -> int | None:
    """Index just after the URL path of an access.log line (to add a query string)."""
    m = ACCESS_RE.search(raw)
    return m.end("url_path") if m else None


def trusted_text(raw: str, source: str) -> str:
    """The log line with all attacker-controlled fields removed."""
    out, last = [], 0
    for span in field_spans(raw, source):
        out.append(raw[last:span.start])
        last = span.end
    out.append(raw[last:])
    return "".join(out)


def label_untrusted(raw: str, source: str) -> str:
    """Put provenance labels around each attacker-controlled field."""
    out, last = [], 0
    for span in field_spans(raw, source):
        out.append(raw[last:span.start])
        out.append(f'<untrusted field="{span.field}">{raw[span.start:span.end]}</untrusted>')
        last = span.end
    out.append(raw[last:])
    return "".join(out)
