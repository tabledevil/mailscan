"""Sprint 7 — email header forensics: spoofing-mismatch heuristics + flags."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear_caches():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _eml(headers: dict, body: str = "hello\n") -> bytes:
    out = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    out += "\r\n" + body
    return out.encode("utf-8")


# ---------------------------------------------------------------
# A1: Reply-To vs From mismatch
# ---------------------------------------------------------------


def test_reply_to_mismatch_high():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "Reply-To": "attacker@evil.example",
        "To": "bob@corp.example",
        "Subject": "t",
        "Message-ID": "<1@corp.example>",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("reply_to_mismatch")
    assert rep is not None
    assert rep.severity == Severity.HIGH


def test_reply_to_match_no_finding():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "Reply-To": "alice@corp.example",
        "To": "bob@corp.example",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "reply_to_mismatch" not in s.analyzer.reports


# ---------------------------------------------------------------
# A2: Return-Path vs From mismatch
# ---------------------------------------------------------------


def test_return_path_mismatch_medium():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "Return-Path": "<bounce@unrelated.example>",
        "To": "bob@corp.example",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("return_path_mismatch")
    assert rep is not None
    assert rep.severity == Severity.MEDIUM


# ---------------------------------------------------------------
# A3: Message-ID domain vs From domain
# ---------------------------------------------------------------


def test_message_id_domain_mismatch():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "To": "bob@corp.example",
        "Subject": "t",
        "Message-ID": "<abc123@randomhost.unrelated.example>",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("message_id_mismatch")
    assert rep is not None, f"reports: {list(s.analyzer.reports)}"
    # LOW severity — common in commodity phishing but also in legitimate
    # forwarded/relayed mail; not worth a MEDIUM flag on its own.
    assert rep.severity == Severity.LOW


def test_message_id_domain_match():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "To": "bob@corp.example",
        "Subject": "t",
        "Message-ID": "<abc123@mta.corp.example>",  # subdomain — still a match
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "message_id_mismatch" not in s.analyzer.reports


def test_message_id_missing_no_finding():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "To": "bob@corp.example",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "message_id_mismatch" not in s.analyzer.reports


# ---------------------------------------------------------------
# A4: undisclosed-recipients flag
# ---------------------------------------------------------------


def test_undisclosed_recipients_flag():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "To": "undisclosed-recipients:;",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("undisclosed_recipients")
    assert rep is not None, f"reports: {list(s.analyzer.reports)}"
    assert rep.severity == Severity.MEDIUM


def test_undisclosed_recipients_case_insensitive():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "To": "Undisclosed-Recipients: ;",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "undisclosed_recipients" in s.analyzer.reports


def test_normal_to_no_undisclosed_finding():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "To": "Bob <bob@corp.example>",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "undisclosed_recipients" not in s.analyzer.reports


# ---------------------------------------------------------------
# Mailing-list suppression — false-positive killer
# ---------------------------------------------------------------


@pytest.mark.parametrize("list_header", ["List-Id", "List-Post",
                                          "List-Unsubscribe", "Mailing-List"])
def test_mailing_list_suppresses_reply_to_mismatch(list_header):
    """SpamAssassin corpus sweep showed legit ML traffic firing HIGH
    reply_to_mismatch; mailing lists routinely set Reply-To to the list."""
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "Reply-To": "thelist@lists.other.example",
        "To": "thelist@lists.other.example",
        list_header: "<thelist.lists.other.example>",
        "Subject": "t",
        "Message-ID": "<1@corp.example>",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "reply_to_mismatch" not in s.analyzer.reports


def test_mailing_list_suppresses_return_path_mismatch():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "Return-Path": "<thelist-bounces@lists.other.example>",
        "List-Id": "<thelist.lists.other.example>",
        "Subject": "t",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "return_path_mismatch" not in s.analyzer.reports


def test_mailing_list_suppresses_message_id_mismatch():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "List-Post": "<mailto:thelist@lists.other.example>",
        "Subject": "t",
        "Message-ID": "<abc@lists.other.example>",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "message_id_mismatch" not in s.analyzer.reports


def test_verp_bounce_sender_suppresses_mismatch():
    data = _eml({
        "From": "Alice <alice@corp.example>",
        "Sender": "list-bounces@lists.other.example",
        "Reply-To": "x@unrelated.example",
        "Subject": "t",
        "Message-ID": "<1@corp.example>",
    })
    s = Structure.create(data=data, filename="t.eml", mime_type="message/rfc822")
    assert "reply_to_mismatch" not in s.analyzer.reports
