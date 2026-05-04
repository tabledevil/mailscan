"""Email forensics extensions — ARC chain, SPF softfail, BCC-leakage."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _eml(headers: dict, body: str = "hello\n") -> bytes:
    out = "".join(f"{k}: {v}\r\n" for k, v in headers.items())
    return (out + "\r\n" + body).encode("utf-8")


def _eml_multi(*header_pairs: tuple[str, str], body: str = "hello\n") -> bytes:
    """Build an eml with potentially repeated header names."""
    out = "".join(f"{k}: {v}\r\n" for k, v in header_pairs)
    return (out + "\r\n" + body).encode("utf-8")


# ---------------------------------------------------------------
# SPF softfail
# ---------------------------------------------------------------


def test_received_spf_softfail_fires_low():
    eml = _eml({
        "Received-SPF": "softfail (mx.example.com: domain transitioning)",
        "From": "a@x.example",
        "To": "b@x.example",
        "Subject": "t",
    })
    s = Structure.create(data=eml, filename="t.eml",
                         mime_type="message/rfc822")
    rep = s.analyzer.reports.get("spf_softfail")
    assert rep is not None
    assert rep.severity == Severity.LOW


def test_received_spf_pass_does_not_fire():
    eml = _eml({
        "Received-SPF": "pass (mx.example.com: 1.2.3.4 is permitted)",
        "From": "a@x.example",
        "To": "b@x.example",
        "Subject": "t",
    })
    s = Structure.create(data=eml, filename="t.eml",
                         mime_type="message/rfc822")
    assert "spf_softfail" not in s.analyzer.reports


def test_received_spf_neutral_does_not_fire():
    eml = _eml({
        "Received-SPF": "neutral",
        "From": "a@x.example",
        "To": "b@x.example",
        "Subject": "t",
    })
    s = Structure.create(data=eml, filename="t.eml",
                         mime_type="message/rfc822")
    assert "spf_softfail" not in s.analyzer.reports


# ---------------------------------------------------------------
# ARC chain depth + cv=fail
# ---------------------------------------------------------------


def test_arc_chain_depth_reported_info_when_clean():
    eml = _eml_multi(
        ("ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=mta1.example; s=arc"),
        ("ARC-Seal", "i=2; a=rsa-sha256; cv=pass; d=mta2.example; s=arc"),
        ("From", "a@x.example"),
        ("To", "b@x.example"),
        ("Subject", "t"),
    )
    s = Structure.create(data=eml, filename="t.eml",
                         mime_type="message/rfc822")
    rep = s.analyzer.reports.get("arc_chain")
    assert rep is not None
    assert rep.data["depth"] == 2
    assert rep.data["cv_fail"] is False
    assert rep.severity == Severity.INFO
    assert "arc_validation_failed" not in s.analyzer.reports


def test_arc_chain_cv_fail_promotes_to_medium():
    eml = _eml_multi(
        ("ARC-Seal", "i=1; a=rsa-sha256; cv=none; d=mta1.example; s=arc"),
        ("ARC-Seal", "i=2; a=rsa-sha256; cv=fail; d=mta2.example; s=arc"),
        ("From", "a@x.example"),
        ("To", "b@x.example"),
        ("Subject", "t"),
    )
    s = Structure.create(data=eml, filename="t.eml",
                         mime_type="message/rfc822")
    rep = s.analyzer.reports.get("arc_chain")
    assert rep is not None
    assert rep.data["cv_fail"] is True
    assert rep.severity == Severity.MEDIUM
    assert "arc_validation_failed" in s.analyzer.reports


def test_no_arc_seals_no_finding():
    eml = _eml({
        "From": "a@x.example",
        "To": "b@x.example",
        "Subject": "t",
    })
    s = Structure.create(data=eml, filename="t.eml",
                         mime_type="message/rfc822")
    assert "arc_chain" not in s.analyzer.reports


# ---------------------------------------------------------------
# BCC leakage — masked To + multi-envelope-target
# ---------------------------------------------------------------


def test_bcc_leakage_with_multiple_envelope_targets_fires():
    """The classic shape: To: undisclosed-recipients, but the Received
    chain shows ``for <victim1@x>`` and ``for <victim2@y>`` etc."""
    eml = _eml_multi(
        ("Received",
         "from x by y with esmtp for <victim1@a.example>; "
         "Mon, 1 Jan 2026 00:00:00 +0000"),
        ("Received",
         "from y by z with esmtp for <victim2@b.example>; "
         "Mon, 1 Jan 2026 00:00:01 +0000"),
        ("From", "attacker@x.example"),
        ("To", "undisclosed-recipients:;"),
        ("Subject", "Mass send"),
    )
    s = Structure.create(data=eml, filename="bulk.eml",
                         mime_type="message/rfc822")
    rep = s.analyzer.reports.get("bcc_leakage")
    assert rep is not None, list(s.analyzer.reports)
    assert rep.severity == Severity.MEDIUM
    assert rep.data["envelope_to_count"] == 2
    assert "victim1@a.example" in rep.data["envelope_tos"]
    assert "victim2@b.example" in rep.data["envelope_tos"]


def test_bcc_leakage_does_not_fire_when_to_visible():
    """If To has a visible address, BCC-bulk-send shape doesn't apply
    even if envelope-Tos differ (legit forwarding)."""
    eml = _eml_multi(
        ("Received",
         "from x by y with esmtp for <bob@a.example>; "
         "Mon, 1 Jan 2026 00:00:00 +0000"),
        ("Received",
         "from y by z with esmtp for <alice@b.example>; "
         "Mon, 1 Jan 2026 00:00:01 +0000"),
        ("From", "sender@x.example"),
        ("To", "bob@a.example"),
        ("Subject", "fwd"),
    )
    s = Structure.create(data=eml, filename="fwd.eml",
                         mime_type="message/rfc822")
    assert "bcc_leakage" not in s.analyzer.reports


def test_bcc_leakage_does_not_fire_with_single_envelope_target():
    """Masked To but only one envelope-To (e.g. group-list rewrites
    that fan out downstream of MATT's view) is benign."""
    eml = _eml_multi(
        ("Received",
         "from x by y with esmtp for <list@a.example>; "
         "Mon, 1 Jan 2026 00:00:00 +0000"),
        ("From", "sender@x.example"),
        ("To", "undisclosed-recipients:;"),
        ("Subject", "list"),
    )
    s = Structure.create(data=eml, filename="list.eml",
                         mime_type="message/rfc822")
    assert "bcc_leakage" not in s.analyzer.reports
