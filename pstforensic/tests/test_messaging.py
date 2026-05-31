"""Messaging-layer tests — Store, Folder, Message, recipients, attachments,
embedded messages, and the named-property map ([MS-PST] §2.4 / PLAN §6).

These drive ONLY the messaging public API (``open_store`` → ``Store`` →
``Folder`` → ``MapiMessage``).  The fixture is the byte-accurate
``synth.build_unicode_pst_tree`` store, which assembles spec-correct HN/PC/TC
payloads (the same geometry the LTP tier round-trips) wired through the real NDB
reader.  Each ``# [MS-PST] §x.y`` / ``# Appendix A Hn`` comment pins the constant
that test locks (governing rule PLAN §0.5).
"""
from __future__ import annotations

import hashlib

import pytest

from pstforensic.catalog import namedprops
from pstforensic.messaging import Folder, Store, open_store
from pstforensic.messaging.attachment import (
    ATTACH_BY_VALUE,
    ATTACH_EMBEDDED_MSG,
)
from pstforensic.messaging.nameid import NamedPropMap, PS_MAPI, PS_PUBLIC_STRINGS
from pstforensic.tests import synth

# PidTag ids used by the assertions ([MS-OXPROPS]).
PID_SUBJECT = 0x0037
PID_SENDER_NAME = 0x0C1A
PID_SENDER_EMAIL = 0x0C1F
PID_DISPLAY_NAME = 0x3001
PID_EMAIL_ADDRESS = 0x3003
PID_ADDRTYPE = 0x3002

# Recipient types ([MS-OXOMSG] §2.2.3.1).
MAPI_TO = 1
MAPI_CC = 2


# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def named_entries():
    """Two named props: one id-named (PSETID_Common LID), one string-named."""
    return [
        {"npid_index": 0, "lid": 0x8580,
         "guid": namedprops.guid_str_to_bytes(namedprops.PSETID_COMMON)},
        {"npid_index": 1, "name": "X-Custom-Header",
         "guid": namedprops.guid_str_to_bytes(namedprops.PS_INTERNET_HEADERS)},
    ]


@pytest.fixture
def store(named_entries) -> Store:
    img = synth.build_unicode_pst_tree(named=named_entries,
                                       pst_password=0xDEADBEEF)
    return open_store(img)


# ---------------------------------------------------------------------------
# Store bootstrap ([MS-PST] §2.4.3 / PLAN §6.1)
# ---------------------------------------------------------------------------
def test_open_store_resolves_message_store_pc():
    # NID_MESSAGE_STORE 0x21 PC → PidTagDisplayName (0x3001) ([MS-PST] §2.4.3).
    img = synth.build_unicode_pst_tree(store_name="My Mailbox")
    st = open_store(img)
    assert isinstance(st, Store)
    assert st.display_name == "My Mailbox"
    assert st.record_key == b"\x11" * 16  # PidTagRecordKey (0x0FF9)
    assert st.nodedb is not None
    assert st.variant.is_unicode


def test_store_password_bypassed_and_flagged(store):
    # PidTagPstPassword (0x67FF): read access needs no password; bypass + flag.
    assert store.has_password is True


def test_store_no_password_when_absent():
    img = synth.build_unicode_pst_tree()  # no pst_password
    st = open_store(img)
    assert st.has_password is False


def test_root_folder_via_ipm_subtree_entryid(store):
    # PidTagIpmSubTreeEntryId (0x35E0) → root folder NID 0x122 ([MS-PST] §2.4.3.1).
    assert store.root_folder is not None
    assert store.root_folder.nid == 0x122
    assert store.root_folder.name == "Personal Folders"
    assert store.root_folder.path == "/Personal Folders"


# ---------------------------------------------------------------------------
# Folder hierarchy ([MS-PST] §2.4.4 / PLAN §6.2)
# ---------------------------------------------------------------------------
def test_folders_recursive_walk(store):
    # folders() is a recursive DFS rooted at the IPM subtree.
    folders = list(store.folders())
    paths = {f.path for f in folders}
    assert "/Personal Folders" in paths
    assert "/Personal Folders/Inbox" in paths
    assert len(folders) == 2


def test_subfolder_derived_from_hierarchy_tc(store):
    # Hierarchy TC (nidType 0x0D) row dwRowID encodes the child folder NID.
    root = store.root_folder
    subs = root.subfolders()
    assert [f.name for f in subs] == ["Inbox"]
    inbox = subs[0]
    assert isinstance(inbox, Folder)
    # Inbox PC NID shares nidIndex with the hierarchy/contents TCs.
    assert inbox.path == "/Personal Folders/Inbox"


def test_folder_messages_from_contents_tc(store):
    # Contents TC (nidType 0x0E) row dwRowID encodes the message NID.
    inbox = store.root_folder.subfolders()[0]
    msgs = inbox.messages()
    subjects = {m.render(PID_SUBJECT) for m in msgs}
    assert subjects == {"Wire transfer", "Lunch?"}


def test_root_folder_has_no_direct_messages(store):
    # The root contents TC is empty in this fixture.
    assert store.root_folder.messages() == []


# ---------------------------------------------------------------------------
# Messages + envelope ([MS-PST] §2.4.5 / PLAN §6.3)
# ---------------------------------------------------------------------------
def _msg(store, subject):
    inbox = store.root_folder.subfolders()[0]
    for m in inbox.messages():
        if m.render(PID_SUBJECT) == subject:
            return m
    raise AssertionError(f"message {subject!r} not found")


def test_message_envelope_fields(store):
    m = _msg(store, "Wire transfer")
    assert m.render(PID_SENDER_NAME) == "Eve Sender"
    assert m.render(PID_SENDER_EMAIL) == "eve@example.com"
    # PidTagMessageClass (0x001A).
    assert m.render(0x001A) == "IPM.Note"


def test_plain_message_has_no_children(store):
    m = _msg(store, "Lunch?")
    assert m.recipients == []
    assert m.attachments == []
    assert m.embedded_messages == []


# ---------------------------------------------------------------------------
# Recipients (Recipient TC, subnode 0x692; [MS-PST] §2.4.5.3 / PLAN §6.4)
# ---------------------------------------------------------------------------
def test_recipients_addresses_and_types(store):
    m = _msg(store, "Wire transfer")
    assert len(m.recipients) == 2
    by_addr = {r.render(PID_EMAIL_ADDRESS): r for r in m.recipients}
    assert set(by_addr) == {"alice@example.com", "bob@example.com"}
    # PidTagRecipientType (0x0C15): 1=To, 2=Cc ([MS-OXOMSG] §2.2.3.1).
    assert by_addr["alice@example.com"].recipient_type == MAPI_TO
    assert by_addr["bob@example.com"].recipient_type == MAPI_CC
    # Display name + address type survive.
    alice = by_addr["alice@example.com"]
    assert alice.render(PID_DISPLAY_NAME) == "Alice"
    assert alice.render(PID_ADDRTYPE) == "SMTP"


# ---------------------------------------------------------------------------
# Attachments (Attachment TC 0x671 → Attachment PCs; [MS-PST] §2.4.6 / App. A H7)
# ---------------------------------------------------------------------------
def test_attachment_by_value_bytes(store):
    m = _msg(store, "Wire transfer")
    by_method = {a.method: a for a in m.attachments}
    assert ATTACH_BY_VALUE in by_method
    att = by_method[ATTACH_BY_VALUE]
    # PidTagAttachLongFilename (0x3707).
    assert att.render(0x3707) == "invoice.pdf"
    # afByValue (1) exposes PidTagAttachDataBinary (0x37010102) lazily.
    assert att.open_data is not None
    data = att.open_data()
    assert data == b"%PDF-1.7 fake invoice bytes"
    # Byte-exact round-trip (axis-D parity intent).
    assert hashlib.sha256(data).hexdigest() == \
        hashlib.sha256(b"%PDF-1.7 fake invoice bytes").hexdigest()


def test_attachment_method_enum_h7(store):
    # Appendix A H7: 5=afEmbeddedMessage, 6=afStorage (embedded/OLE NOT swapped).
    m = _msg(store, "Wire transfer")
    methods = {a.method for a in m.attachments}
    assert methods == {ATTACH_BY_VALUE, ATTACH_EMBEDDED_MSG}  # {1, 5}


def test_embedded_message_recursion(store):
    # afEmbeddedMessage (5): __substg 0x3701000D subnode → nested Message PC.
    m = _msg(store, "Wire transfer")
    assert len(m.embedded_messages) == 1
    emb = m.embedded_messages[0]
    assert emb.render(PID_SUBJECT) == "Embedded note"
    assert emb.render(PID_SENDER_EMAIL) == "carol@example.com"
    # The embedded message is reachable via the attachment too.
    embed_att = next(a for a in m.attachments if a.method == ATTACH_EMBEDDED_MSG)
    assert embed_att.embedded is emb


# ---------------------------------------------------------------------------
# Named-property map (NID_NAME_TO_ID_MAP 0x61; Appendix A H17 / PLAN §6.6)
# ---------------------------------------------------------------------------
def test_named_props_loaded(store):
    assert len(store.named_props) == 2


def test_named_prop_id_named_resolves_lid(store):
    # NPID 0x8000 → (PSETID_Common GUID, LID 0x8580) → PidLidInternetAccountName.
    np = store.named_props.resolve(0x8000)
    assert np is not None
    assert np.lid == 0x8580
    assert np.guid == namedprops.PSETID_COMMON
    assert store.named_props.label(0x8000) == "PidLidInternetAccountName"


def test_named_prop_string_named_resolves_name(store):
    # NPID 0x8001 → string-named "X-Custom-Header" in PS_INTERNET_HEADERS.
    np = store.named_props.resolve(0x8001)
    assert np is not None
    assert np.is_string
    assert np.name == "X-Custom-Header"
    assert np.guid == namedprops.PS_INTERNET_HEADERS
    assert store.named_props.label(0x8001) == "X-Custom-Header"


def test_named_prop_wguid_hardcodes_h17():
    # Appendix A H17: wGuid 1=PS_MAPI, 2=PS_PUBLIC_STRINGS are hardcoded and
    # NOT present in the GUID stream; >=3 indexes GuidStream[wGuid-3].
    import struct
    # Two entries: wGuid=1 (PS_MAPI) id-named, wGuid=2 (PS_PUBLIC_STRINGS) id-named.
    entry = struct.pack("<IHH", 0x1234, (1 << 1) | 0, 0)
    entry += struct.pack("<IHH", 0x5678, (2 << 1) | 0, 1)
    m = NamedPropMap.from_streams(b"", entry, b"")
    assert m.resolve(0x8000).guid == PS_MAPI
    assert m.resolve(0x8001).guid == PS_PUBLIC_STRINGS


def test_named_prop_missing_map_degrades(store=None):
    # AC-5: absent NID 0x61 → empty map + NAMEID_MISSING flag, no crash.
    img = synth.build_unicode_pst_tree()  # no named props node
    st = open_store(img)
    assert len(st.named_props) == 0
    assert st.named_props.resolve(0x8000) is None
    from pstforensic.exceptions import WarnCode
    assert WarnCode.NAMEID_MISSING in {w.code for w in st.warnings}


# ---------------------------------------------------------------------------
# Robustness: no hard-CRC failures on the clean fixture
# ---------------------------------------------------------------------------
def test_clean_store_has_no_crc_failures(store):
    from pstforensic.exceptions import WarnCode
    codes = {w.code for w in store.warnings}
    assert WarnCode.PAGE_CRC_FAIL not in codes
    assert WarnCode.HEADER_CRC_FAIL not in codes
    assert WarnCode.BLOCK_CRC_FAIL not in codes
