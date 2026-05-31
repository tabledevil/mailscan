"""NDB-layer round-trip + structural tests (locks every parsed constant).

Each test names the [MS-PST] section whose constant it pins (PLAN §0.5: no
byte-level constant is trusted without a vector).  The synth writer in
``synth.py`` is the oracle: writer→reader round-trips prove the header, ROOT,
B-tree, block, XBLOCK, subnode and crypt code agree byte-for-byte.
"""
from __future__ import annotations

import pytest

from pstforensic import WarnCode
from pstforensic.exceptions import (
    EncryptedStoreError,
    NotAPstError,
    UnsupportedStoreError,
    WarningSink,
)
from pstforensic.fileio import FileReader
from pstforensic.ndb import bref, crypt
from pstforensic.ndb.crc import compute_crc, compute_crc_bitwise, compute_sig
from pstforensic.ndb.nodedb import NodeDatabase
from pstforensic.variant import (
    ANSI,
    CRYPT_CYCLIC,
    CRYPT_NONE,
    CRYPT_PERMUTE,
    UNICODE,
)
from pstforensic.tests import synth

MSGS = [
    {"subject": "Hello", "sender": "a@x.com", "to": "b@y.com", "body": "Body one",
     "props": {0x0037001F: "Hello".encode("utf-16-le")}},
    {"subject": "Second", "sender": "c@x.com", "to": "d@y.com", "body": "Body two"},
]


def _expected_payloads(messages):
    return [synth._message_payload(m) for m in messages]


# --- BID / NID normalization ([MS-PST] §2.2.2.1-§2.2.2.2) -------------------
def test_bid_reserved_bit_cleared():
    # Reserved bit 0x1 cleared before BBT lookup; internal 0x2 retained (H22).
    assert bref.normalize_bid(0x4 | 0x1) == 0x4
    assert bref.normalize_bid(0x4 | 0x2 | 0x1) == 0x4 | 0x2
    assert bref.bid_is_internal(0x4 | 0x2) is True
    assert bref.bid_is_internal(0x4) is False


def test_nid_type_and_index():
    # NID = nidType(5 bits) + nidIndex ([MS-PST] §2.2.2.1).
    nid = bref.make_nid(0x04, 0x123)
    assert bref.nid_type(nid) == 0x04
    assert bref.nid_index(nid) == 0x123
    # NID_MESSAGE_STORE special.
    assert bref.NID_MESSAGE_STORE == 0x21


# --- CRC / sig (already foundation, re-locked through the table path) -------
def test_crc_matches_bitwise_oracle():
    data = bytes(range(256)) * 3
    assert compute_crc(data) == compute_crc_bitwise(data)


def test_sig_xor_fold():
    # ComputeSig(ib,bid)=WORD((x>>16)^x), x=ib^bid ([MS-PST] §5.5).
    assert compute_sig(0, 0) == 0
    x = 0x1234 ^ 0xABCD
    assert compute_sig(0x1234, 0xABCD) == ((x >> 16) ^ x) & 0xFFFF


# --- crypt round-trips ([MS-PST] §5.1/§5.2) --------------------------------
@pytest.mark.parametrize("method", [CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC])
def test_crypt_roundtrip(method):
    data = bytes(range(256)) * 5 + b"the quick brown fox"
    bid = 0x84
    enc = crypt.encode_block(data, method, bid)
    dec = crypt.decode_block(enc, method, bid)
    assert dec == data
    if method != CRYPT_NONE:
        assert enc != data  # actually transforms


def test_crypt_table_self_checks():
    # mpbbCrypt is exactly 768 bytes and PERMUTE map is bijective (PLAN §0.5).
    assert len(crypt.mpbbCrypt) == 768
    assert sorted(crypt._ENCODE_MAP) == list(range(256))


def test_detect_encode_picks_method():
    plain = b"\xecHN-signature-here" + bytes(range(64))
    bid = 0x40
    enc = crypt.encode_block(plain, CRYPT_PERMUTE, bid)
    got = crypt.detect_encode(lambda b: b[:1] == b"\xec", enc, bid)
    assert got is not None
    method, decoded = got
    assert decoded == plain


# --- header detection ([MS-PST] §2.2.2.6 / Appendix A.2) -------------------
def test_unicode_header_parse():
    img = synth.build_unicode_pst(messages=MSGS)
    db = NodeDatabase.open(FileReader(img))
    assert db.variant is UNICODE
    assert db.crypt_method == CRYPT_NONE
    assert db.header.wver == 23
    assert db.header.crc_partial_ok is True
    assert db.header.crc_full_ok is True
    assert db.header.root.ib_file_eof == len(img)


def test_ansi_header_parse():
    img = synth.build_ansi_pst(messages=MSGS)
    db = NodeDatabase.open(FileReader(img))
    assert db.variant is ANSI
    assert db.header.wver == 14
    assert db.header.crc_partial_ok is True
    assert db.header.crc_full_ok is None  # ANSI has no dwCRCFull
    assert db.header.root.ib_file_eof == len(img)


def test_not_a_pst_raises():
    with pytest.raises(NotAPstError):
        NodeDatabase.open(FileReader(b"NOTAPST!" + b"\x00" * 600))


def test_unknown_wver_unsupported():
    img = bytearray(synth.build_unicode_pst(messages=MSGS))
    import struct
    struct.pack_into("<H", img, 0x0A, 9)  # wVer=9 unrecognised
    with pytest.raises(UnsupportedStoreError):
        NodeDatabase.open(FileReader(bytes(img)))


def test_edp_encrypted_raises():
    img = bytearray(synth.build_unicode_pst(messages=MSGS))
    img[UNICODE.crypt_method_offset] = 0x10  # NDB_CRYPT_EDPCRYPTED
    with pytest.raises(EncryptedStoreError):
        NodeDatabase.open(FileReader(bytes(img)))


# --- round-trip: nodes & data streams --------------------------------------
@pytest.mark.parametrize("builder,variant", [
    (synth.build_unicode_pst, UNICODE),
    (synth.build_ansi_pst, ANSI),
])
@pytest.mark.parametrize("method", [CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC])
def test_node_data_roundtrip(builder, variant, method):
    img = builder(messages=MSGS, crypt=method)
    sink = WarningSink()
    db = NodeDatabase.open(FileReader(img, sink=sink), sink=sink)
    expected = _expected_payloads(MSGS)
    for idx, exp in enumerate(expected):
        nid = bref.make_nid(bref.NID_TYPE_NORMAL_MESSAGE, idx + 1)
        ref = db.node(nid)
        assert ref is not None, f"node {nid:#x} missing"
        assert ref.data_stream() == exp
    # No structural failures on a clean store (CRC/sig all pass).
    bad = {WarnCode.BLOCK_CRC_FAIL, WarnCode.PAGE_CRC_FAIL,
           WarnCode.HEADER_CRC_FAIL, WarnCode.SIG_MISMATCH,
           WarnCode.ENTRY_OVERFLOW, WarnCode.OUT_OF_BOUNDS}
    assert not (sink.codes() & bad), sink.codes()


def test_iter_nbt_bbt_counts():
    img = synth.build_unicode_pst(messages=MSGS)
    db = NodeDatabase.open(FileReader(img))
    assert len(list(db.iter_nbt())) == len(MSGS)
    # one data block per message.
    assert len(list(db.iter_bbt())) == len(MSGS)


# --- XBLOCK reassembly ([MS-PST] §2.2.2.8.3.2) -----------------------------
@pytest.mark.parametrize("method", [CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC])
def test_xblock_reassembly(method):
    img = synth.build_unicode_pst(messages=MSGS, crypt=method, big_message=True)
    db = NodeDatabase.open(FileReader(img))
    nid = bref.make_nid(bref.NID_TYPE_NORMAL_MESSAGE, 1)
    ref = db.node(nid)
    assert ref.data_stream() == synth._message_payload(MSGS[0])


# --- subnode tree ([MS-PST] §2.2.2.8.3.3) ----------------------------------
def test_subnode_tree():
    msgs = [{"subject": "S", "body": "B",
             "subnodes": {0x10: b"recip-table-bytes",
                          0x20: b"attach-table-bytes"}}]
    img = synth.build_unicode_pst(messages=msgs)
    db = NodeDatabase.open(FileReader(img))
    nid = bref.make_nid(bref.NID_TYPE_NORMAL_MESSAGE, 1)
    ref = db.node(nid)
    subs = ref.subnodes()
    assert set(subs) == {0x10, 0x20}
    assert subs[0x10].data_stream() == b"recip-table-bytes"
    assert subs[0x20].data_stream() == b"attach-table-bytes"


def test_subnode_tree_ansi():
    msgs = [{"subject": "S", "subnodes": {0x11: b"hello-subnode"}}]
    img = synth.build_ansi_pst(messages=msgs)
    db = NodeDatabase.open(FileReader(img))
    nid = bref.make_nid(bref.NID_TYPE_NORMAL_MESSAGE, 1)
    subs = db.node(nid).subnodes()
    assert subs[0x11].data_stream() == b"hello-subnode"


# --- CRC advisory (warn, never abort) --------------------------------------
def test_header_crc_advisory():
    img = synth.build_unicode_pst(messages=MSGS, corrupt="bad_header_crc")
    sink = WarningSink()
    db = NodeDatabase.open(FileReader(img, sink=sink), sink=sink)  # must NOT raise
    assert WarnCode.HEADER_CRC_FAIL in sink.codes()
    # Still fully readable.
    nid = bref.make_nid(bref.NID_TYPE_NORMAL_MESSAGE, 1)
    assert db.node(nid).data_stream() == synth._message_payload(MSGS[0])


def test_amap_invalid_advisory():
    img = synth.build_unicode_pst(messages=MSGS, corrupt="zero_amap")
    sink = WarningSink()
    NodeDatabase.open(FileReader(img, sink=sink), sink=sink)
    assert WarnCode.AMAP_INVALID in sink.codes()


def test_drop_nbt_entry_loses_node():
    img = synth.build_unicode_pst(messages=MSGS, corrupt="drop_nbt_entry")
    db = NodeDatabase.open(FileReader(img))
    # The second message node is dropped by lowering cEnt.
    assert len(list(db.iter_nbt())) == len(MSGS) - 1


def test_truncated_does_not_crash():
    img = synth.build_unicode_pst(messages=MSGS, corrupt="truncate")
    sink = WarningSink()
    # Header may still parse but blocks/pages are gone — must not raise.
    try:
        NodeDatabase.open(FileReader(img, sink=sink), sink=sink)
    except NotAPstError:
        pass  # extreme truncation can drop magic; acceptable
    assert sink.codes()  # something was flagged


# --- bounds / overflow guards ----------------------------------------------
def test_entry_overflow_guard():
    img = bytearray(synth.build_unicode_pst(messages=MSGS))
    # Inflate cEnt on the NBT page to an impossible value -> ENTRY_OVERFLOW.
    page = UNICODE.page_size
    nbt_start = len(img) - page
    cent_off = nbt_start + page - UNICODE.page_trailer_size - 4 - 4
    img[cent_off] = 255
    sink = WarningSink()
    NodeDatabase.open(FileReader(bytes(img), sink=sink), sink=sink)
    assert WarnCode.ENTRY_OVERFLOW in sink.codes()


def test_block_free_region_info():
    img = synth.build_unicode_pst(messages=MSGS)
    db = NodeDatabase.open(FileReader(img))
    info = db.free_region_info()
    assert info["ib_file_eof"] == len(img)
    assert len(info["live_block_extents"]) == len(MSGS)


# --- MSG builder (CFBF) -----------------------------------------------------
def test_build_msg_cfbf_roundtrips_via_olefile():
    olefile = pytest.importorskip("olefile")
    blob = synth.build_msg(props={
        0x0037001F: "Subject".encode("utf-16-le"),
        0x0C1F001F: "sender@x.com".encode("utf-16-le"),
    })
    import io
    assert olefile.isOleFile(io.BytesIO(blob))
    ole = olefile.OleFileIO(io.BytesIO(blob))
    names = ["".join(p) for p in ole.listdir()]
    assert "__properties_version1.0" in names
    assert "__substg1.0_0037001F" in names
    data = ole.openstream("__substg1.0_0037001F").read()
    assert data == "Subject".encode("utf-16-le")
    ole.close()


def test_build_msg_flat_fallback_shape():
    # Even without olefile the builder returns bytes with a properties stream.
    blob = synth.build_msg(props={0x0037001F: b"hi"})
    assert isinstance(blob, (bytes, bytearray)) and len(blob) > 0
