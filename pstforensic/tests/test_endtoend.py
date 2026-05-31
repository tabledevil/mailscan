"""End-to-end integration tests — the PUBLIC API only (PLAN §1.3 axis D-lite).

These tests deliberately import *only* the package's documented public surface
(``pstforensic.open_store``, ``pstforensic.open_msg``,
``pstforensic.RecoveryEngine`` and the ``MapiMessage`` model) and drive a
byte-accurate synthetic store/MSG produced by :mod:`pstforensic.tests.synth`.
They assert **human-readable rendered values** (not raw bytes), proving the full
pipeline header → NDB → LTP → render → messaging → recovery wires together.

Each ``# [MS-PST]/[MS-OXxxx] §`` comment pins the constant the assertion locks
(governing rule PLAN §0.5).
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

import pstforensic
from pstforensic import MapiMessage, open_msg, open_store
from pstforensic.catalog import namedprops
from pstforensic.proptypes import PropType, make_tag
from pstforensic.recovery import RecoveryEngine
from pstforensic.tests import synth

# PidTag ids exercised ([MS-OXPROPS]).
PID_SUBJECT = 0x0037           # PidTagSubject
PID_SENDER_NAME = 0x0C1A       # PidTagSenderName
PID_SENDER_EMAIL = 0x0C1F      # PidTagSenderEmailAddress
PID_BODY = 0x1000              # PidTagBody
PID_DELIVERY_TIME = 0x0E06     # PidTagMessageDeliveryTime
PID_DISPLAY_NAME = 0x3001      # PidTagDisplayName
PID_EMAIL_ADDRESS = 0x3003     # PidTagEmailAddress


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def named_entries():
    """One id-named (PSETID_Common LID 0x8580) and one string-named prop."""
    return [
        {"npid_index": 0, "lid": 0x8580,
         "guid": namedprops.guid_str_to_bytes(namedprops.PSETID_COMMON)},
        {"npid_index": 1, "name": "X-Custom-Header",
         "guid": namedprops.guid_str_to_bytes(namedprops.PS_INTERNET_HEADERS)},
    ]


@pytest.fixture
def store_bytes(named_entries) -> bytes:
    """A multi-folder PST with recipients, attachments AND a deleted message."""
    return synth.build_unicode_pst_tree(
        store_name="Case Mailbox", named=named_entries,
        pst_password=0xC0FFEE, deleted=True)


# ---------------------------------------------------------------------------
# open_store → walk folders → render an envelope (the headline workflow)
# ---------------------------------------------------------------------------
def test_open_store_walks_folders_and_renders_message(store_bytes):
    # Public entry point: bytes → Store ([MS-PST] §2.4.3 bootstrap).
    store = open_store(store_bytes)
    assert store.display_name == "Case Mailbox"

    # Walk the folder tree ONCE (the root carries a shared visited-set cycle
    # guard; a second independent walk is intentionally short-circuited).
    folders = list(store.folders())
    paths = [f.path for f in folders]
    assert "/Case Mailbox" in paths
    assert "/Case Mailbox/Inbox" in paths

    inbox = next(f for f in folders if f.name == "Inbox")
    msgs = inbox.messages()
    # Two LIVE messages in Inbox (the deleted one is NOT referenced here).
    assert len(msgs) == 2

    wire = next(m for m in msgs if m.render(PID_SUBJECT) == "Wire transfer")
    assert isinstance(wire, MapiMessage)

    # Human-readable renders (NOT raw bytes) — render dispatcher (PLAN §9.8).
    assert wire.render(PID_SUBJECT) == "Wire transfer"
    assert wire.render(PID_SENDER_NAME) == "Eve Sender"
    assert wire.render(PID_SENDER_EMAIL) == "eve@example.com"
    assert wire.render(PID_BODY) == "Please wire $1,000,000 today."

    # PidTagMessageDeliveryTime (0x0E06) → real UTC datetime (FILETIME, §9.3).
    dt = wire.render(PID_DELIVERY_TIME)
    assert dt == datetime(2021, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def test_open_store_recipients_and_attachments_render(store_bytes):
    store = open_store(store_bytes)
    inbox = next(f for f in store.folders() if f.name == "Inbox")  # single walk
    wire = next(m for m in inbox.messages()
                if m.render(PID_SUBJECT) == "Wire transfer")

    # Recipient TC (subnode 0x692): To + Cc, rendered to readable strings.
    emails = sorted(r.render(PID_EMAIL_ADDRESS) for r in wire.recipients)
    assert emails == ["alice@example.com", "bob@example.com"]

    # Attachment TC (subnode 0x671): one by-value PDF + one embedded message.
    fnames = sorted(a.render(0x3707) for a in wire.attachments)  # PidTagAttachLongFilename
    assert "invoice.pdf" in fnames
    assert "forwarded.msg" in fnames
    # Embedded message recursion ([MS-OXMSG]/§10.x).
    assert len(wire.embedded_messages) == 1
    assert wire.embedded_messages[0].render(PID_SUBJECT) == "Embedded note"


def test_open_store_resolves_named_property(store_bytes):
    # Named-prop map (NID 0x61): NPID 0x8000 → id-named LID 0x8580 in
    # PSETID_Common → PidLidInternetAccountName ([MS-OXPROPS], §6.6).
    store = open_store(store_bytes)
    np = store.named_props
    resolved = np.resolve(0x8000)
    assert resolved is not None
    assert resolved.lid == 0x8580
    # The catalog renders the LID to a human label.
    assert np.label(0x8000) == "PidLidInternetAccountName"
    # The string-named entry resolves to its literal name.
    assert np.label(0x8001) == "X-Custom-Header"


# ---------------------------------------------------------------------------
# RecoveryEngine surfaces the deleted item (PLAN §8.2)
# ---------------------------------------------------------------------------
def test_recovery_engine_surfaces_deleted_message(store_bytes):
    items = RecoveryEngine(store_bytes).recover()
    assert len(items) == 1
    item = items[0]

    # The deleted item's envelope survived → readable subject/body.
    assert item.subject == "Deleted secret"
    assert item.message is not None
    assert item.message.render(PID_BODY) == "This message was deleted."

    # Provenance: attributed to its claimed parent folder, honest confidence band
    # (NOT 1.0 — a hard-deleted item ranks below a live one, Appendix A H15).
    assert item.meta.method == "btree"
    assert item.meta.attributed_folder == "/Case Mailbox/Inbox"
    assert 0.0 < item.meta.confidence < 1.0
    assert item.meta.recovery_class in ("pc_body_only", "pc_plus_subnode")


def test_recovery_engine_clean_store_has_no_deleted_items():
    # A store with no orphaned nodes yields an empty recovery set (no false +).
    clean = synth.build_unicode_pst_tree(deleted=False)
    assert RecoveryEngine(clean).recover() == []


def test_recovery_engine_exposed_at_package_root():
    # pstforensic.RecoveryEngine is part of the documented public surface.
    assert pstforensic.RecoveryEngine is RecoveryEngine


# ---------------------------------------------------------------------------
# open_msg for a native MSG (PLAN §10.1)
# ---------------------------------------------------------------------------
@pytest.fixture
def msg_bytes() -> bytes:
    pytest.importorskip("olefile")
    return synth.build_msg(props={
        make_tag(0x0037, PropType.STRING): "RE: SWIFT payment".encode("utf-16-le"),
        make_tag(0x0C1F, PropType.STRING): "alice@example.com".encode("utf-16-le"),
        make_tag(0x1000, PropType.STRING): "Please review the attached.".encode("utf-16-le"),
    })


def test_open_msg_renders_envelope(msg_bytes):
    from pstforensic.render import install_renderer

    msg = open_msg(msg_bytes)
    install_renderer(msg)
    assert isinstance(msg, MapiMessage)
    # Human-readable renders from the CFBF __substg1.0 streams ([MS-OXMSG] §2).
    assert msg.render(make_tag(0x0037, PropType.STRING)) == "RE: SWIFT payment"
    assert msg.render(make_tag(0x0C1F, PropType.STRING)) == "alice@example.com"
    assert msg.render(make_tag(0x1000, PropType.STRING)) == "Please review the attached."
