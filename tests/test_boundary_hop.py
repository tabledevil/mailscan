"""Sprint 7 — A6: first-external-hop callout."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker
from Utils.relay_cache import RelayCache


@pytest.fixture(autouse=True)
def _isolated(tmp_path):
    Structure.clear_cache()
    PasswordBroker.clear()
    RelayCache.reset(str(tmp_path / "relay_cache.json"))
    yield
    Structure.clear_cache()
    PasswordBroker.clear()
    RelayCache.reset()


def _eml(received: list[str], extra_headers: dict | None = None) -> bytes:
    out = ""
    for r in received:
        out += f"Received: {r}\r\n"
    out += "From: a@a.example\r\nTo: b@b.example\r\nSubject: t\r\n"
    out += "Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n"
    if extra_headers:
        for k, v in extra_headers.items():
            out += f"{k}: {v}\r\n"
    out += "\r\nbody\n"
    return out.encode("utf-8")


def test_boundary_hop_identifies_microsoft_365():
    received = [
        # Newest first (Received headers prepend)
        "from AMS1EPF0000008E.eurprd05.prod.outlook.com by GV2P194MB2591.EURP194.PROD.OUTLOOK.COM "
        "with ESMTPS; Mon, 1 Jan 2026 00:00:05 +0000",
        "from a.example (a.example. [203.0.113.5]) "
        "by AMS1EPF0000008E.mail.protection.outlook.com (Postfix) with ESMTPS id ABC "
        "for <to@x>; Mon, 1 Jan 2026 00:00:00 +0000",
    ]
    s = Structure.create(data=_eml(received), filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("mail_boundary")
    assert rep is not None, f"reports: {list(s.analyzer.reports)}"
    assert "protection.outlook.com" in rep.text
    assert "microsoft-365" in rep.text


def test_no_boundary_when_no_known_gateway():
    received = [
        "from a.example by b.example with ESMTPS; "
        "Mon, 1 Jan 2026 00:00:00 +0000",
    ]
    s = Structure.create(data=_eml(received), filename="t.eml", mime_type="message/rfc822")
    assert "mail_boundary" not in s.analyzer.reports


def test_boundary_picks_first_external_gateway_not_subsequent_hops():
    """If the chain crosses Mimecast first, then continues through M365, the
    boundary should name Mimecast — not the later M365 hops."""
    received = [
        # newest hop (last in chronological order) — internal M365
        "from a.eu-smtp-1.mimecast.com by AMS1EPF0000008E.mail.protection.outlook.com "
        "with ESMTPS; Mon, 1 Jan 2026 00:00:10 +0000",
        # boundary hop
        "from a.example (a.example. [203.0.113.5]) "
        "by eu-smtp-1.mimecast.com (Postfix) with ESMTPS id ABC "
        "for <to@x>; Mon, 1 Jan 2026 00:00:00 +0000",
    ]
    s = Structure.create(data=_eml(received), filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("mail_boundary")
    assert rep is not None
    assert "mimecast" in rep.text.lower()
