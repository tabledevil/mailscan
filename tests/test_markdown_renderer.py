"""Sprint 7 — B2: markdown renderer polish."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _md(headers: dict, body: str = "hello\n") -> str:
    raw = "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + "\r\n" + body
    s = Structure.create(data=raw.encode("utf-8"), filename="t.eml",
                         mime_type="message/rfc822")
    return s.get_report(report_format="markdown", verbosity=0)


def test_markdown_emits_sha1_and_sha256():
    out = _md({"From": "a@x.example", "To": "b@x.example", "Subject": "t"})
    assert "**MD5**:" in out
    assert "**SHA1**:" in out
    assert "**SHA256**:" in out


def test_markdown_severity_badge_on_high_finding():
    out = _md({
        "From": "a@corp.example",
        "Reply-To": "x@evil.example",
        "To": "b@corp.example",
        "Subject": "t",
        "Message-ID": "<1@corp.example>",
    })
    assert "HIGH" in out


def test_markdown_no_severity_badge_for_info_only():
    out = _md({"From": "a@x.example", "To": "b@x.example", "Subject": "t"})
    # INFO findings should NOT carry HIGH/CRITICAL emoji prefixes
    assert "🟥" not in out
    assert "🟧" not in out
    # MEDIUM is acceptable since iocs_aggregate may bump severity if
    # the body contains URLs; ensure the emoji is at least recognized form


def test_markdown_no_empty_label_brackets():
    """Empty labels used to render as '****: ...'. Report.label autofill
    should make this impossible now."""
    out = _md({"From": "a@x.example", "To": "b@x.example", "Subject": "t"})
    assert "****:" not in out


def test_markdown_aggregate_iocs_present():
    out = _md(
        {"From": "a@x.example", "To": "b@x.example", "Subject": "t"},
        body="See http://malicious.example.com/ and 8.8.8.8\n",
    )
    assert "iocs" in out.lower()
    # Defang propagated through extraction
    assert "malicious" in out
