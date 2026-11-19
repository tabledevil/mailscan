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
