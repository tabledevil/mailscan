"""Known-answer recovery tests ([MS-PST] / PLAN §7-§8 / Appendix A).

Drives the FULL recovery cascade against byte-accurate synthetic corruption
fixtures (``synth.build_unicode_pst*`` ``corrupt=`` knobs) — the shared oracle,
so every assertion below is a *known answer*, not a self-fulfilling round-trip.

Acceptance criteria covered (PLAN §1.3 / Appendix A):
  * AC-2 (``truncate``)        — survivor-prefix messages, method != 'btree'.
  * AC-4 (``bad_header_crc``)  — clean-twin items still read; HEADER_CRC_FAIL.
  * AC-3 (``zero_amap``)       — item set identical to the clean twin.
  * drop_nbt_entry            — removed message recovered as orphan/hard with
                                 confidence < 1.0 and a correct recovery class.
Plus unit coverage: carve finds a known block, encode_detect picks the right
method (NONE/PERMUTE/CYCLIC), dedup collapses identical copies, and the
free-space three-set algebra (Appendix A H14).

Each ``# [MS-PST]/Appendix A`` comment pins the constant the assertion locks
(governing rule PLAN §0.5).
"""
from __future__ import annotations

import pytest

from pstforensic.fileio import FileReader
from pstforensic.recovery import (
    RecoveryEngine,
    carve,
    compute_free_space,
    dedup,
    detect_encode_method,
)
from pstforensic.recovery.dedup import envelope_key, raw_key
from pstforensic.recovery.engine import RecoveredItem
from pstforensic.recovery.score import RecoveryMeta
from pstforensic.ndb.bref import NID_TYPE_NORMAL_MESSAGE, nid_type
from pstforensic.ndb.block import block_disk_size
from pstforensic.variant import CRYPT_CYCLIC, CRYPT_NONE, CRYPT_PERMUTE, UNICODE
from pstforensic.tests import synth

# PidTag ids exercised ([MS-OXPROPS]).
PID_SUBJECT = 0x0037
PID_BODY = 0x1000
PID_MESSAGE_CLASS = 0x001A


def _subjects(items):
    return sorted(i.subject for i in items if i.subject)


# ---------------------------------------------------------------------------
# AC-2 — truncate → survivor-prefix carve (PLAN §7.2, method != 'btree')
# ---------------------------------------------------------------------------
def test_ac2_truncate_recovers_survivor_prefix_via_carve():
    """corrupt='truncate' drops the trailing BBT/NBT pages; the surviving message
    PC blocks are recovered by the carve fallback, NOT the trusted B-tree walk."""
    img = synth.build_unicode_pst_tree(deleted=True, corrupt="truncate")
    eng = RecoveryEngine(img)
    assert eng._roots_broken  # trusted ROOT walk is unusable (§7.2)

    items = eng.recover()
    # Every survivor-prefix message PC is recovered (Wire transfer / Lunch? /
    # Deleted secret all carry IPM.Note — the §7.6 cross-validation gate).
    assert "Deleted secret" in _subjects(items)
    assert "Wire transfer" in _subjects(items)
    assert len(items) >= 1

    # AC-2: none came from the trusted btree walk — all via the carve cascade.
    assert all(it.meta.method != "btree" for it in items)
    assert all(it.meta.method in ("carve_hard", "orphan_pc") for it in items)
    # Honest confidence: a carved item ranks below a live tree item (H15).
    assert all(0.0 < it.meta.confidence < 1.0 for it in items)


# ---------------------------------------------------------------------------
# AC-4 — bad_header_crc → still reads, HEADER_CRC_FAIL surfaced (advisory CRC)
# ---------------------------------------------------------------------------
def test_ac4_bad_header_crc_still_reads_and_warns():
    """corrupt='bad_header_crc' flips dwCRCPartial; the CRC is advisory ([MS-PST]
    §2.2.2.6) so the clean-twin item set still reads, but HEADER_CRC_FAIL warns."""
    clean = synth.build_unicode_pst_tree(deleted=True)
    bad = synth.build_unicode_pst_tree(deleted=True, corrupt="bad_header_crc")

    clean_items = RecoveryEngine(clean).recover()
    eng = RecoveryEngine(bad)
    bad_items = eng.recover()

    # AC-4: same items as the clean twin despite the bad header CRC.
    assert _subjects(bad_items) == _subjects(clean_items)
    assert _subjects(bad_items) == ["Deleted secret"]

    # The advisory CRC failure is recorded (never aborts).
    assert "HEADER_CRC_FAIL" in eng.sink.codes()


# ---------------------------------------------------------------------------
# AC-3 — zero_amap → identical to clean twin (free space ≠ AMap, H14)
# ---------------------------------------------------------------------------
def test_ac3_zero_amap_item_set_identical_to_clean_twin():
    """corrupt='zero_amap' marks fAMapValid invalid; recovery never trusts the
    on-disk AMap (Appendix A H14), so the recovered set is identical."""
    clean = synth.build_unicode_pst_tree(deleted=True)
    zeroed = synth.build_unicode_pst_tree(deleted=True, corrupt="zero_amap")

    clean_items = RecoveryEngine(clean).recover()
    zero_items = RecoveryEngine(zeroed).recover()

    assert _subjects(zero_items) == _subjects(clean_items)
    # Both surface exactly the one deleted message at equal confidence.
    assert len(zero_items) == len(clean_items) == 1
    assert zero_items[0].meta.confidence == clean_items[0].meta.confidence


# ---------------------------------------------------------------------------
# drop_nbt_entry → removed message recovered as orphan-PC, confidence < 1.0
# ---------------------------------------------------------------------------
def test_drop_nbt_entry_recovers_message_as_orphan():
    """corrupt='drop_nbt_entry' removes the last NBTENTRY; its data block stays
    allocated but unreferenced → recovered as an orphan PC (PLAN §8.3)."""
    img = synth.build_unicode_pst_tree(deleted=True, corrupt="drop_nbt_entry")
    eng = RecoveryEngine(img)
    items = eng.recover()

    assert "Deleted secret" in _subjects(items)
    secret = next(i for i in items if i.subject == "Deleted secret")

    # An allocated-but-unreferenced block → orphan-PC class, honest band (H15).
    assert secret.meta.method in ("orphan_pc", "carve_hard")
    assert secret.meta.confidence < 1.0
    assert secret.meta.recovery_class in (
        "pc_body_only", "pc_plus_subnode",
        "attachment_or_recipient_orphan", "partial_fragment")
    # The envelope survived the NBT drop → readable body.
    assert secret.message is not None
    assert secret.message.render(PID_BODY) == "This message was deleted."


def test_clean_store_has_no_false_positive_recovery():
    """A store with every block referenced yields an empty recovery set."""
    clean = synth.build_unicode_pst_tree(deleted=False)
    assert RecoveryEngine(clean).recover() == []


# ---------------------------------------------------------------------------
# carve.py — linear scan finds a known synthetic block (PLAN §7.2)
# ---------------------------------------------------------------------------
def test_carve_finds_known_synthetic_block():
    """The full-file carve recovers the message node's NBTENTRY, its BBTENTRY,
    and the data block by trailer signature ([MS-PST] §2.2.2.7.1/§2.2.2.8.1)."""
    img = synth.build_unicode_pst(messages=[
        {"subject": "X", "sender": "a", "to": "b", "body": "carve me please"}])
    res = carve(FileReader(img), UNICODE)

    # The normal-message node (nidType 0x04) is among the carved NBT entries.
    carved_msg = [e for e in res.nbt_entries
                  if nid_type(e.nid) == NID_TYPE_NORMAL_MESSAGE]
    assert carved_msg, "carve must recover the message NBTENTRY"
    # Its referenced data block carved as a validated block trailer.
    assert res.blocks, "carve must recover at least one data block"
    assert res.block_candidates >= 1
    assert res.page_candidates >= 2  # one BBT page + one NBT page


# ---------------------------------------------------------------------------
# encode_detect.py — picks the right method for NONE/PERMUTE/CYCLIC
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("crypt", [CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC])
def test_encode_detect_picks_correct_method(crypt):
    """detect_encode_method trial-decodes a message PC block and recovers the
    store's crypt method by the HN ``bSig 0xEC`` signal ([MS-PST] §5.1/§5.2).

    NOTE (Appendix A H21): this proves round-trip detection against the synth
    oracle, not the absolute decode of a proprietary Outlook block.
    """
    img = synth.build_unicode_pst_tree(crypt=crypt)
    eng = RecoveryEngine(img)
    db = eng.nodedb

    ent = next(e for e in db.iter_nbt()
               if nid_type(e.nid) == NID_TYPE_NORMAL_MESSAGE)
    bbt = next(b for b in db.iter_bbt() if b.bid == ent.bid_data)
    disk = block_disk_size(bbt.cb, UNICODE)
    encoded = eng._reader.read(bbt.bref.ib, disk)[: bbt.cb]

    guess = detect_encode_method(encoded, ent.bid_data)
    assert guess is not None
    assert guess.hn_sig_ok
    assert guess.crypt_method == crypt


# ---------------------------------------------------------------------------
# dedup.py — collapses two identical carved copies (PLAN §8.6)
# ---------------------------------------------------------------------------
def test_dedup_collapses_identical_carved_copies():
    """Two carves of the same raw PC bytes collapse to one survivor; the higher
    confidence wins and duplicate_count records the collapse (PLAN §8.6)."""
    m_lo = RecoveryMeta(method="carve_hard", confidence=0.70, raw_pc=b"SAME")
    m_hi = RecoveryMeta(method="carve_hard", confidence=0.82, raw_pc=b"SAME")
    a = RecoveredItem(nid=1, message=None, meta=m_lo, subject=None)
    b = RecoveredItem(nid=2, message=None, meta=m_hi, subject=None)

    out = dedup([a, b])
    assert len(out) == 1
    assert out[0].meta.confidence == 0.82       # highest-confidence kept
    assert out[0].meta.duplicate_count == 2     # both collapses recorded

    # Distinct raw bytes do NOT collapse.
    c = RecoveredItem(nid=3, message=None,
                      meta=RecoveryMeta(method="carve_hard", confidence=0.7,
                                        raw_pc=b"OTHER"), subject=None)
    out2 = dedup([a, c])
    assert len(out2) == 2


def test_dedup_keys_distinguish_raw_payloads():
    """raw_key is content-addressed: same bytes → same key, different → different."""
    m1 = RecoveryMeta(method="carve_hard", confidence=0.7, raw_pc=b"AAA")
    m2 = RecoveryMeta(method="carve_hard", confidence=0.7, raw_pc=b"AAA")
    m3 = RecoveryMeta(method="carve_hard", confidence=0.7, raw_pc=b"BBB")
    i1 = RecoveredItem(nid=1, message=None, meta=m1, subject=None)
    i2 = RecoveredItem(nid=2, message=None, meta=m2, subject=None)
    i3 = RecoveredItem(nid=3, message=None, meta=m3, subject=None)
    # No message → envelope incomplete → raw-PC-bytes key (PLAN §8.6).
    assert envelope_key(i1) is None
    assert raw_key(i1) == raw_key(i2)
    assert raw_key(i1) != raw_key(i3)


# ---------------------------------------------------------------------------
# score.py — the free-space THREE-set algebra (Appendix A H14)
# ---------------------------------------------------------------------------
def test_free_space_three_set_algebra():
    """free_for_carving = file span − rebuilt-reachable (the robust H14 signal);
    on_disk_free and disagreement are reported separately, never as the source."""
    fs = compute_free_space(
        file_size=1000,
        reachable_extents=[(0, 100), (200, 300)],
        on_disk_free=[(100, 200), (400, 1000)])

    # Primary signal: complement of the reachable set.
    assert fs.free_for_carving == [(100, 200), (300, 1000)]
    assert fs.rebuilt_reachable == [(0, 100), (200, 300)]
    # on_disk_free is preserved verbatim (normalized).
    assert fs.on_disk_free == [(100, 200), (400, 1000)]
    # Disagreement = on_disk_free XOR free_for_carving — the [300,400) region
    # carving claims free but the on-disk AMap does not.  NEVER the carve source.
    assert fs.disagreement == [(300, 400)]


def test_free_space_carving_equals_full_span_when_nothing_reachable():
    """With an empty rebuilt BBT the whole file is free for carving (§7.2)."""
    fs = compute_free_space(file_size=512, reachable_extents=[])
    assert fs.free_for_carving == [(0, 512)]
    assert fs.rebuilt_reachable == []


# ---------------------------------------------------------------------------
# rebuild.py + advisory AMap (in-memory only — Appendix A N1)
# ---------------------------------------------------------------------------
def test_rebuild_index_and_advisory_amap_never_touch_file():
    """rebuild_index reconciles carved entries; reconstruct_amap is in-memory."""
    from pstforensic.recovery.rebuild import rebuild_index, reconstruct_amap

    img = synth.build_unicode_pst(messages=[
        {"subject": "X", "sender": "a", "to": "b", "body": "rebuild me"}])
    res = carve(FileReader(img), UNICODE)
    idx = rebuild_index(res)
    assert idx.bbt          # at least the message data block
    assert idx.nbt          # at least the message node

    amap = reconstruct_amap(idx.bbt, UNICODE, file_size=len(img))
    # Advisory sentinel and granule are recorded for provenance only.
    assert amap.f_amap_valid_advisory == 0x02
    assert amap.granule == UNICODE.block_align
    assert amap.allocated_extents  # every rebuilt block marked allocated
