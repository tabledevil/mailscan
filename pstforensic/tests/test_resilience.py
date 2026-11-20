"""Kernel-parity resilience: tolerant reading, strict per-object findings (PLAN §14).

Acceptance gates locked here:
  * a healthy store yields only live items and the scan keeps nothing extra;
  * deletion residue (stale NBT pages, slack beyond cEnt, freed blocks) comes
    back as exactly the deleted / superseded items, with provenance;
  * structures planted inside a live block's payload (an attached PST) never
    become items;
  * damage is read through and flagged on the object it affects.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from pstforensic import open_store
from pstforensic.fileio import FileReader
from pstforensic.ndb.block import block_disk_size
from pstforensic.ndb.btree import PTYPE_BBT
from pstforensic.ndb.crc import compute_crc
from pstforensic.ndb.nodedb import NodeDatabase
from pstforensic.ndb.scan import scan_file
from pstforensic.variant import CRYPT_CYCLIC, CRYPT_NONE, CRYPT_PERMUTE, UNICODE

from . import synth

RESIDUE = dict(hard_deleted=True, slack_deleted=True, superseded=True, moved=True)


def _scan(img, use_numpy=None):
    r = FileReader(img)
    db = NodeDatabase.open(r)
    return scan_file(r, db.variant, live_nbt=db._nbt, live_bbt=db._bbt,
                     live_page_ibs=set(db.page_verdicts), use_numpy=use_numpy)


def _summary(ix):
    return (sorted((s.entry.nid, s.entry.bid_data, s.entry.nid_parent, s.beyond_cent)
                   for s in ix.slots),
            sorted((b.bid, b.ib, b.crc_ok, b.sig_ok)
                   for bs in ix.blocks.values() for b in bs),
            sorted((p.ib, p.variant, p.ptype) for p in ix.pages))


# --- zero-garbage gate ------------------------------------------------------
@pytest.mark.parametrize("crypt", [CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC])
def test_healthy_store_yields_only_live_items(crypt):
    st = open_store(synth.build_unicode_pst_tree(crypt=crypt))
    items = st.items()
    assert [i.state for i in items] == ["live", "live"]
    assert all(i.integrity.ok for i in items)
    assert st.integrity.ok, st.integrity.findings
    scan = st.scan()
    assert scan.slots == [] and scan.blocks == {}


@pytest.mark.parametrize("builder", [synth.build_unicode_pst, synth.build_ansi_pst])
def test_healthy_flat_store_scan_keeps_nothing(builder):
    img = builder(messages=[{"subject": "a", "body": "x"}, {"subject": "b"}])
    ix = _scan(img)
    assert ix.slots == [] and ix.blocks == {} and ix.bbt_entries == []


@pytest.mark.parametrize("kw", [{}, RESIDUE, {"deleted": True}])
def test_numpy_and_pure_python_scan_identical(kw):
    pytest.importorskip("numpy")
    img = synth.build_unicode_pst_tree(**kw)
    assert _summary(_scan(img, use_numpy=True)) == _summary(_scan(img, use_numpy=False))


# --- deletion residue -------------------------------------------------------
def test_deletion_residue_inventory():
    st = open_store(synth.build_unicode_pst_tree(**RESIDUE))
    by = {(i.state, i.subject): i for i in st.items()}
    assert set(by) == {
        ("live", "Wire transfer"), ("live", "Lunch?"),
        ("deleted", "Hard deleted"), ("deleted", "Slack deleted"),
        ("superseded", "Lunch? (draft)"),
    }
    hard = by[("deleted", "Hard deleted")]
    assert hard.provenance == "stale_page"
    assert hard.folder_path == "/Personal Folders/Inbox"
    assert hard.deletion.kind == "hard"
    assert hard.deletion.original_folder == "/Personal Folders/Inbox"
    assert "BLOCK_FROM_SCAN" in hard.integrity.codes
    assert hard.message.render(0x1000) == "Gone from the NBT, still on disk."

    slack = by[("deleted", "Slack deleted")]
    assert slack.provenance == "slack_slot"

    draft = by[("superseded", "Lunch? (draft)")]
    lunch = by[("live", "Lunch?")]
    assert draft.supersedes == lunch.nid
    # Identical content under another parent is history, not an item.
    assert [(h.kind, h.folder_path) for h in lunch.history] == [
        ("moved", "/Personal Folders")]


def test_deletion_time_is_never_invented():
    st = open_store(synth.build_unicode_pst_tree(hard_deleted=True))
    hard = next(i for i in st.items() if i.state == "deleted")
    # No PidTagDeletedOn in a local PST: only a lower bound, with its source.
    assert hard.deletion.deleted_on is None
    assert hard.deletion.not_before == datetime(2021, 6, 15, 12, tzinfo=timezone.utc)
    assert hard.deletion.not_before_source == "PidTagMessageDeliveryTime"


def test_orphan_in_live_nbt():
    st = open_store(synth.build_unicode_pst_tree(deleted=True))
    orphan = [i for i in st.items() if i.state == "orphan"]
    assert [i.subject for i in orphan] == ["Deleted secret"]
    assert orphan[0].deletion.kind == "orphan"


# --- false-positive suppression ----------------------------------------------
def _plant_store_in_live_block(img: bytes) -> bytes:
    """Write a fully valid NBT leaf page + message block (sig computed for their
    *absolute* offsets, CRCs valid) into the payload of a live filler block,
    then fix the filler block's own CRC — the worst case of an attached PST."""
    buf = bytearray(img)
    db = NodeDatabase.open(FileReader(bytes(buf)))
    filler = max(db._bbt.values(), key=lambda e: e.cb)
    base = filler.bref.ib
    v = UNICODE

    trap_bid, trap_nid, inbox = 0x9990, 0x9984, 0x142
    pc = synth.build_pc_bytes({
        synth._PID_SUBJECT: "PHANTOM".encode("utf-16-le"),
        synth._PID_MESSAGE_CLASS: "IPM.Note".encode("utf-16-le"),
    })
    blk_ib = base + 512
    blk = synth._Block(bid=trap_bid, payload=pc, internal=False, ib=blk_ib)
    buf[blk_ib:blk_ib + block_disk_size(len(pc), v)] = synth._emit_block(blk, v)

    ent = struct.pack("<QQQII", trap_nid, trap_bid, 0, inbox, 0)
    body = ent + b"\x00" * (0x1E8 - len(ent)) + bytes([1, 15, 32, 0]) + b"\x00" * 4
    page = body + synth._page_trailer(0x81, base, 0x77, body, v)
    buf[base:base + 512] = page

    # Re-seal the filler block so it stays a verified live block.
    disk = block_disk_size(filler.cb, v)
    tr_off = base + disk - v.block_trailer_size
    struct.pack_into("<I", buf, tr_off + 4, compute_crc(bytes(buf[base:base + filler.cb])))
    return bytes(buf)


def test_structures_inside_live_block_never_become_items():
    img = _plant_store_in_live_block(synth.build_unicode_pst_tree(filler_block=2048))
    ix = _scan(img)
    assert ix.stats.pages_suppressed >= 1
    assert ix.slots == [] and ix.blocks == {}
    st = open_store(img)
    assert {i.subject for i in st.items()} == {"Wire transfer", "Lunch?"}


# --- damage is read through and flagged ----------------------------------------
def test_block_crc_damage_flagged_on_item():
    img = bytearray(synth.build_unicode_pst_tree())
    db = NodeDatabase.open(FileReader(bytes(img)))
    ent = db._bbt[db.node(0x44).bid_data]           # msg 2 ("Lunch?") PC block
    disk = block_disk_size(ent.cb, UNICODE)
    crc_off = ent.bref.ib + disk - UNICODE.block_trailer_size + 4
    img[crc_off] ^= 0xFF                             # CRC field only: data intact
    st = open_store(bytes(img))
    by = {i.subject: i for i in st.items()}
    assert by["Lunch?"].state == "live_damaged"
    assert "BLOCK_CRC_FAIL" in by["Lunch?"].integrity.codes
    assert by["Wire transfer"].state == "live"


def test_destroyed_bbt_page_still_reads_every_message():
    # Kernel's case: the B-tree is broken, the data is all there.
    img = bytearray(synth.build_unicode_pst_tree())
    db = NodeDatabase.open(FileReader(bytes(img)))
    bbt_root = db.header.root.bref_bbt.ib
    img[bbt_root + 0x1F0:bbt_root + 0x200] = b"\x00" * 16   # trailer gone
    img[bbt_root + 0x1E8:bbt_root + 0x1EC] = b"\x00" * 4    # counters gone
    st = open_store(bytes(img))
    items = st.items()
    assert {i.subject for i in items} == {"Wire transfer", "Lunch?"}
    assert "PAGE_UNREADABLE" in st.integrity.codes
    for i in items:
        assert "BLOCK_FROM_SCAN" in i.integrity.codes
    wire = next(i for i in items if i.subject == "Wire transfer")
    assert len(wire.message.attachments) == 2


def test_scan_abort_is_reported():
    st = open_store(synth.build_unicode_pst_tree(**RESIDUE))
    scan = st.scan(should_abort=lambda: True)
    assert scan.complete is False
    assert "SCAN_INCOMPLETE" in st.integrity.codes


def test_folder_walk_is_repeatable():
    st = open_store(synth.build_unicode_pst_tree())
    first = [f.path for f in st.folders()]
    assert first == [f.path for f in st.folders()] == [
        "/Personal Folders", "/Personal Folders/Inbox"]


# --- damaged NBT: the Kernel case ------------------------------------------------
def _nbt_pages(img):
    db = NodeDatabase.open(FileReader(bytes(img)))
    root = db.header.root.bref_nbt.ib
    leaves = [ib for ib, v in db.page_verdicts.items()
              if v.ptype == 0x81 and ib != root]
    return db, root, leaves


def test_destroyed_inner_nbt_page_items_stay_live():
    img = bytearray(synth.build_unicode_pst_tree(extra_messages=40))
    _db, root, _leaves = _nbt_pages(img)
    img[root + 0x1E8:root + 0x200] = b"\x00" * 0x18    # counters + trailer gone
    st = open_store(bytes(img))
    items = st.items()
    assert len(items) == 42
    assert {i.state for i in items} == {"live_damaged"}
    assert all(i.provenance == "scan_nbt" for i in items)
    assert all("NODE_FROM_SCAN" in i.integrity.codes for i in items)
    assert {i.folder_path for i in items} == {"/Personal Folders/Inbox"}
    assert "PAGE_UNREADABLE" in st.integrity.codes


def test_nbt_leaf_crc_damage_flagged_not_fatal():
    img = bytearray(synth.build_unicode_pst_tree(extra_messages=40))
    _db, _root, leaves = _nbt_pages(img)
    leaf = sorted(leaves)[-1]
    img[leaf + 0x1F0 + 4] ^= 0xFF                        # page dwCRC only
    st = open_store(bytes(img))
    items = st.items()
    assert len(items) == 42
    hit = [i for i in items if "PAGE_CRC_FAIL" in i.integrity.codes]
    assert hit and all(i.state == "live_damaged" for i in hit)
    assert all(i.provenance == "btree" for i in items)


def test_unreachable_entry_with_damaged_nbt_is_lost_not_deleted():
    img = bytearray(synth.build_unicode_pst_tree(hard_deleted=True, extra_messages=40))
    _db, root, _leaves = _nbt_pages(img)
    img[root + 0x1E8:root + 0x200] = b"\x00" * 0x18
    st = open_store(bytes(img))
    by = {i.subject: i for i in st.items()}
    assert by["Hard deleted"].state == "lost"
    assert by["Hard deleted"].deletion.kind == "unknown"


# --- crypt ladder ------------------------------------------------------------
@pytest.mark.parametrize("header_value", [CRYPT_NONE, CRYPT_CYCLIC, 0x55])
def test_wrong_crypt_header_decodes_from_evidence(header_value):
    img = bytearray(synth.build_unicode_pst_tree(crypt=CRYPT_PERMUTE))
    img[UNICODE.crypt_method_offset] = header_value
    st = open_store(bytes(img))
    by = {i.subject: i for i in st.items()}
    assert set(by) == {"Wire transfer", "Lunch?"}
    assert by["Wire transfer"].message.render(0x1000) == "Please wire $1,000,000 today."
    assert all("CRYPT_FROM_EVIDENCE" in i.integrity.codes for i in by.values())
    if header_value == 0x55:
        assert "CRYPT_METHOD_UNKNOWN" in st.integrity.codes


def test_correct_crypt_header_has_no_crypt_findings():
    st = open_store(synth.build_unicode_pst_tree(crypt=CRYPT_CYCLIC))
    for i in st.items():
        assert not {c for c in i.integrity.codes if c.startswith("CRYPT")}


# --- carving & salvage --------------------------------------------------------------
def test_unreferenced_freed_message_is_carved_once():
    st = open_store(synth.build_unicode_pst_tree(carvable=True))
    items = st.items()
    carved = [i for i in items if i.state == "carved"]
    assert [i.subject for i in carved] == ["Only in free space"]
    c = carved[0]
    assert c.provenance == "free_space" and c.nid == 0 and c.bid
    assert {"BLOCK_FROM_SCAN", "SUBNODES_UNKNOWN"} <= c.integrity.codes
    assert c.deletion.kind == "hard"
    # The freed exact copy of a live message collapses into it.
    assert st.inventory_stats.carved_duplicates == 1
    assert sum(1 for i in items if i.subject == "Lunch?") == 1


def test_embedded_message_pc_is_not_carved_twice():
    st = open_store(synth.build_unicode_pst_tree(hard_deleted=True, carvable=True))
    subjects = [i.subject for i in st.items()]
    assert "Embedded note" not in subjects


def test_recover_offers_older_versions_and_fragments():
    st = open_store(synth.build_unicode_pst_tree(**RESIDUE))
    items = st.items()
    lunch = next(i for i in items if i.state == "live" and i.subject == "Lunch?")
    res = lunch.recover()
    assert [a.subject for a in res.alternatives] == ["Lunch? (draft)"]
    assert "Lunch?" in " ".join(res.fragments)
    hard = next(i for i in items if i.subject == "Hard deleted")
    assert any("Gone from the NBT" in f for f in hard.recover().fragments)


def test_recover_rereads_from_a_verified_copy():
    # Damage msg 2's live PC block payload; plant an intact copy of the same
    # BID elsewhere (as a freed block) — recover() must prefer it.
    img = bytearray(synth.build_unicode_pst_tree())
    db = NodeDatabase.open(FileReader(bytes(img)))
    ent = db._bbt[db.node(0x44).bid_data]
    good = bytes(img[ent.bref.ib:ent.bref.ib + ent.cb])
    tail = len(img) + (-len(img) % 512)               # copy lives past the old EOF
    img.extend(b"\x00" * (tail - len(img)))
    copy = synth._Block(bid=ent.bref.raw_bid, payload=good, internal=False, ib=tail)
    img.extend(synth._emit_block(copy, UNICODE))
    img[ent.bref.ib + 8] ^= 0xFF                      # corrupt the live payload
    st = open_store(bytes(img))
    lunch = next(i for i in st.items() if i.nid == 0x44)
    assert "BLOCK_CRC_FAIL" in lunch.integrity.codes
    res = lunch.recover()
    assert "RECOVERED_ALT_COPY" in res.item.integrity.codes
    assert res.item.subject == "Lunch?"


def test_wiped_header_store_still_reads_everything():
    # First two header pages zeroed (e.g. wiped sectors): magic, wVer, ROOT,
    # bCryptMethod all gone.  Kernel opens such files; so must we.
    img = bytearray(synth.build_unicode_pst_tree(crypt=CRYPT_PERMUTE, extra_messages=5))
    img[0:0x400] = b"\x00" * 0x400
    st = open_store(bytes(img))
    items = st.items()
    assert {i.subject for i in items} >= {"Wire transfer", "Lunch?", "Bulk 0", "Bulk 4"}
    assert all(i.state == "live_damaged" for i in items)
    assert {i.folder_path for i in items} == {"/Personal Folders/Inbox"}
    assert {"HEADER_UNUSABLE", "CRYPT_METHOD_UNKNOWN"} <= st.integrity.codes
    wire = next(i for i in items if i.subject == "Wire transfer")
    assert wire.message.render(0x1000) == "Please wire $1,000,000 today."


@pytest.mark.parametrize("use_numpy", [True, False])
def test_scan_finds_4k_block_per_kernel_layout(use_numpy):
    from pstforensic.ndb.crc import compute_sig
    from pstforensic.variant import UNICODE_4K
    if use_numpy:
        pytest.importorskip("numpy")
    buf = bytearray(8192)
    payload = b"X" * 100
    ib, bid = 1024, 0x44
    buf[ib:ib + 100] = payload
    struct.pack_into("<HHIQ", buf, ib + 0x1E8, 100, compute_sig(ib, bid),
                     compute_crc(payload), bid)
    ix = scan_file(FileReader(bytes(buf)), UNICODE_4K, variants=(UNICODE_4K,),
                   use_numpy=use_numpy)
    (blk,) = ix.blocks[0x44]
    assert (blk.ib, blk.cb, blk.strong, blk.variant) == (1024, 100, True, "unicode4k")


# --- corruption matrix: one defect each — found AND flagged -------------------------
def _patch(img, off, data):
    img[off:off + len(data)] = data


def _defect(name):
    img = bytearray(synth.build_unicode_pst_tree(extra_messages=20))
    db = NodeDatabase.open(FileReader(bytes(img)))
    root = db.header.root
    nbt_leaves = sorted(ib for ib, v in db.page_verdicts.items()
                        if v.ptype == 0x81 and ib != root.bref_nbt.ib)
    msg2 = db._bbt[db.node(0x44).bid_data]
    msg2_tr = msg2.bref.ib + block_disk_size(msg2.cb, UNICODE) - UNICODE.block_trailer_size
    if name == "magic":
        _patch(img, 0, b"XXXX")
    elif name == "header_crc":
        img[4] ^= 0xFF
    elif name == "wver":
        _patch(img, 0x0A, struct.pack("<H", 99))
    elif name == "crypt_field":
        img[UNICODE.crypt_method_offset] = 0x33
    elif name == "amap":
        img[UNICODE.root_offset + 4 + 4 * 8 + 2 * 16] = 0
    elif name == "nbt_root_trailer":
        _patch(img, root.bref_nbt.ib + 0x1E8, b"\x00" * 0x18)
    elif name == "nbt_leaf_crc":
        img[nbt_leaves[0] + 0x1F4] ^= 0xFF
    elif name == "nbt_leaf_sig":
        img[nbt_leaves[0] + 0x1F2] ^= 0xFF
    elif name == "bbt_root_trailer":
        _patch(img, root.bref_bbt.ib + 0x1E8, b"\x00" * 0x18)
    elif name == "block_crc":
        img[msg2_tr + 4] ^= 0xFF
    elif name == "block_sig":
        img[msg2_tr + 2] ^= 0xFF
    elif name == "block_bid":
        img[msg2_tr + 8] ^= 0x40
    elif name == "header_wiped":
        _patch(img, 0, b"\x00" * 0x400)
    return bytes(img)


MATRIX = {
    # defect: (store-level codes, codes on at least one item)
    "magic": ({"HEADER_MAGIC_BAD"}, set()),
    "header_crc": ({"HEADER_CRC_FAIL"}, set()),
    "wver": ({"WVER_UNUSUAL"}, set()),
    "crypt_field": ({"CRYPT_METHOD_UNKNOWN"}, {"CRYPT_FROM_EVIDENCE"}),
    "amap": ({"AMAP_INVALID"}, set()),
    "nbt_root_trailer": ({"PAGE_UNREADABLE"}, {"NODE_FROM_SCAN"}),
    "nbt_leaf_crc": ({"PAGE_CRC_FAIL"}, {"PAGE_CRC_FAIL"}),
    "nbt_leaf_sig": ({"PAGE_SIG_FAIL"}, {"PAGE_SIG_FAIL"}),
    "bbt_root_trailer": ({"PAGE_UNREADABLE"}, {"BLOCK_FROM_SCAN"}),
    "block_crc": (set(), {"BLOCK_CRC_FAIL"}),
    "block_sig": (set(), {"BLOCK_SIG_FAIL"}),
    "block_bid": (set(), {"BLOCK_BID_MISMATCH"}),
    "header_wiped": ({"HEADER_UNUSABLE"}, {"NODE_FROM_SCAN"}),
}


@pytest.mark.parametrize("defect", sorted(MATRIX))
def test_corruption_matrix(defect):
    store_codes, item_codes = MATRIX[defect]
    st = open_store(_defect(defect))
    items = st.items()
    # Every message is still there, and nothing else appears.
    assert sorted(i.subject for i in items) == sorted(
        ["Wire transfer", "Lunch?"] + [f"Bulk {n}" for n in range(20)])
    assert {i.state for i in items} <= {"live", "live_damaged"}
    assert store_codes <= st.integrity.codes, st.integrity.codes
    found = set().union(*(i.integrity.codes for i in items))
    assert item_codes <= found, found
    if not item_codes:
        assert all(i.state == "live" for i in items)


# --- crypt tables (locked after the mpbbS transcription bug) --------------------
def test_mpbbcrypt_tables_locked():
    import hashlib
    from pstforensic.ndb import crypt as C
    assert hashlib.sha256(C.mpbbCrypt).hexdigest() == \
        "4281e754d24c215779e404b732da252e734a74eba1f8648c494c4d1260e55c7c"
    R, S, I = bytes(C._MPBB_R), bytes(C._MPBB_S), bytes(C._MPBB_I)
    assert all(I[R[b]] == b for b in range(256))      # I = R^-1
    assert all(S[S[b]] == b for b in range(256))      # S self-inverse


def test_cyclic_is_an_involution_and_paths_agree():
    import os
    from pstforensic.ndb import crypt as C
    data = os.urandom(5000)
    for bid in (0x4, 0x1234, 0xFFFF0010, 0x123456789A):
        enc = C.crypt_cyclic(data, bid)
        assert enc != data
        assert C.crypt_cyclic(enc, bid) == data
        np_ = C._np
        try:
            C._np = None                                    # pure-Python path
            assert C.crypt_cyclic(data, bid) == enc
        finally:
            C._np = np_


def test_cyclic_matches_spec_literal():
    # Straight transcription of [MS-PST] §5.2 CryptCyclic, byte by byte.
    from pstforensic.ndb import crypt as C
    R, S, I = bytes(C._MPBB_R), bytes(C._MPBB_S), bytes(C._MPBB_I)
    key = 0xBEEF1234
    w = (key ^ (key >> 16)) & 0xFFFF
    data = bytes(range(256)) * 3
    out = bytearray()
    for byte in data:
        b = (byte + (w & 0xFF)) & 0xFF
        b = R[b]
        b = (b + (w >> 8)) & 0xFF
        b = S[b]
        b = (b - (w >> 8)) & 0xFF
        b = I[b]
        b = (b - (w & 0xFF)) & 0xFF
        out.append(b)
        w = (w + 1) & 0xFFFF
    assert C.crypt_cyclic(data, key) == bytes(out)


# --- diagnostics & debug log are content-free --------------------------------------
def test_diagnostics_record_failures_without_leaking_messages(monkeypatch, tmp_path):
    import json
    import logging
    from pstforensic.log import enable_debug_log
    from pstforensic.messaging import inventory as inv_mod
    secret = "Top-Secret-Subject-Line"

    def boom(*a, **k):
        raise UnicodeDecodeError("utf-8", secret.encode(), 0, 1, secret)

    log_path = tmp_path / "debug.log"
    handler = enable_debug_log(str(log_path), logging.DEBUG)
    try:
        monkeypatch.setattr(inv_mod, "build_message", boom)
        st = open_store(synth.build_unicode_pst_tree(hard_deleted=True))
        st.items()
        diag = st.diagnostics()
    finally:
        logging.getLogger("pstforensic").removeHandler(handler)
        handler.close()
    blob = json.dumps(diag, default=str)
    assert secret not in blob
    assert secret not in log_path.read_text()
    fails = diag["failures"]
    assert fails and fails[0]["exception"] == "UnicodeDecodeError"
    assert fails[0]["phase"] == "build_message"
    assert "test_resilience.py" in fails[0]["location"] or "inventory.py" in fails[0]["location"]
    assert diag["reasons"].get("unresolved_deleted:exception") == 1
    assert diag["environment"]["pstforensic"]


def test_summary_tool_never_raises(tmp_path):
    from pstforensic.tools.summary import summarize
    p = tmp_path / "junk.pst"
    p.write_bytes(b"\x00" * 8192)
    out = summarize(str(p))
    assert out["failed_phase"] == "open"
    assert out["exception"] == "NotAPstError"
    assert "fingerprint" in out
