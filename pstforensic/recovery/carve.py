"""Signature carving — linear full-file scan for valid trailers (PLAN §7.2).

When the ROOT B-tree roots are broken/truncated/zeroed, the trusted walk
(:mod:`pstforensic.recovery.engine` Stage 0) cannot reach the NBT/BBT leaf
pages.  This module recovers the leaf entries anyway by scanning the *whole
file* for structurally-valid trailers:

  * **PAGETRAILER** ([MS-PST] §2.2.2.7.1) at page-aligned offsets, validated by
    ``ptype in {0x80, 0x81}`` ∧ ``ptype == ptypeRepeat`` ∧
    :func:`pstforensic.ndb.crc.compute_sig` matching ``wSig`` ∧ (CRC match OR a
    plausible counter region).  A valid BBT (0x80) / NBT (0x81) page is then
    parsed for its BBTENTRY / NBTENTRY leaves.
  * **BLOCKTRAILER** ([MS-PST] §2.2.2.8.1) at 64-byte-aligned block ends,
    validated by ``cb`` sane ∧ normalized ``bid`` in range ∧ ``wSig`` matching
    ∧ (CRC of the ``cb`` payload bytes matching, when available).

False-positive suppression follows PLAN §7.2 / Appendix A: a candidate is only
promoted when the signature *and* (CRC **or** an alignment+range consistency
check) agree.  Zeroed regions (``ptype == 0x00``) are rejected outright.

Nothing here writes the file; carving is read-only forensic recovery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from ..exceptions import WarningSink
from ..fileio import FileReader
from ..ndb.bref import normalize_bid
from ..ndb.btree import (
    PTYPE_BBT,
    PTYPE_NBT,
    BBTEntry,
    NBTEntry,
    _page_counters,
    _parse_bbt_entry,
    _parse_nbt_entry,
    entries_region_size,
    parse_page_trailer,
)
from ..ndb.block import block_disk_size, parse_block_trailer
from ..ndb.crc import compute_crc, compute_sig
from ..variant import Variant


@dataclass
class CarvedBlock:
    """A block whose BLOCKTRAILER carved cleanly from free/raw space (§7.2).

    Attributes:
        ib: Absolute file offset of the block's first byte.
        bid: Normalized block BID (BBT lookup key).
        cb: Payload length in bytes (from the trailer).
        crc_ok: True iff the trailer CRC over the ``cb`` payload matched.
        sig_ok: True iff ``compute_sig(ib, raw_bid)`` matched the trailer wSig.
        payload: The ``cb`` raw payload bytes (still encoded if the store is).
    """

    ib: int
    bid: int
    cb: int
    crc_ok: bool
    sig_ok: bool
    payload: bytes


@dataclass
class CarveResult:
    """Everything :func:`carve` recovered from a linear scan (§7.2/§7.3 feed)."""

    bbt_entries: List[BBTEntry] = field(default_factory=list)
    nbt_entries: List[NBTEntry] = field(default_factory=list)
    blocks: List[CarvedBlock] = field(default_factory=list)
    pages_scanned: int = 0
    page_candidates: int = 0
    block_candidates: int = 0


def _page_trailer_valid(page: bytes, ib: int, variant: Variant) -> Optional[int]:
    """Return the page's ptype if its PAGETRAILER is a valid BBT/NBT trailer.

    Validates ``ptype in {0x80, 0x81}`` ∧ ``ptype == ptypeRepeat`` ∧ the
    XOR-fold signature ([MS-PST] §5.5) ∧ (CRC match OR a sane counter region),
    rejecting zeroed pages (``ptype == 0``).  Returns ``None`` on any failure.
    """
    if len(page) < variant.page_size:
        return None
    tr = parse_page_trailer(page, variant)
    if tr.ptype == 0x00:
        return None
    if tr.ptype not in (PTYPE_BBT, PTYPE_NBT):
        return None
    if tr.ptype != tr.ptype_repeat:
        return None
    if compute_sig(ib, tr.bid) != tr.w_sig:
        return None
    body = page[: variant.page_size - variant.page_trailer_size]
    crc_ok = compute_crc(body) == tr.dw_crc
    if crc_ok:
        return tr.ptype
    # No CRC match → demand a structurally plausible counter region instead.
    c_ent, c_ent_max, cb_ent, c_level = _page_counters(page, variant)
    region = entries_region_size(variant)
    if cb_ent == 0 or c_ent == 0 or c_ent * cb_ent > region:
        return None
    if c_ent > c_ent_max or c_ent_max * cb_ent > region:
        return None
    return tr.ptype


def _carve_leaf_entries(page: bytes, ptype: int, variant: Variant,
                        file_size: int) -> tuple[list, bool]:
    """Parse BBT/NBT leaf entries out of a validated page (best-effort).

    Returns ``(entries, is_leaf)``.  Intermediate pages (``cLevel > 0``) carry
    BTENTRYs that point at child pages, not leaves, so they yield no entries
    here — the linear scan reaches those child pages independently.
    """
    c_ent, c_ent_max, cb_ent, c_level = _page_counters(page, variant)
    region = entries_region_size(variant)
    if cb_ent == 0:
        return [], False
    max_fit = region // cb_ent
    if c_ent > max_fit:
        c_ent = max_fit
    if c_level > 0:
        return [], False  # intermediate page; leaves found via their own pages
    out = []
    for i in range(c_ent):
        off = i * cb_ent
        if ptype == PTYPE_BBT:
            ent = _parse_bbt_entry(page, off, variant)
            if 0 <= ent.bref.ib < file_size and ent.cb > 0:
                out.append(ent)
        else:
            ent = _parse_nbt_entry(page, off, variant)
            out.append(ent)
    return out, True


def _block_trailer_valid(reader: FileReader, ib: int, cb: int,
                         variant: Variant) -> Optional[CarvedBlock]:
    """Validate a candidate BLOCKTRAILER whose block starts at ``ib``.

    ``cb`` is read from the trailer at ``ib + disk - trailer_size``.  Requires a
    normalized ``bid`` in range, on-disk footprint within the file, signature
    match, and (when present) a CRC match over the ``cb`` payload bytes
    ([MS-PST] §2.2.2.8.1).  Returns a :class:`CarvedBlock` or ``None``.
    """
    if cb <= 0 or cb > variant.page_size * 512:
        return None
    disk = block_disk_size(cb, variant)
    buf = reader.read(ib, disk)
    if len(buf) < disk:
        return None
    tr = parse_block_trailer(buf, variant)
    if tr.cb != cb:
        return None
    bid = normalize_bid(tr.bid)
    if bid <= 0:
        return None
    if compute_sig(ib, tr.bid) != tr.w_sig:
        return None
    payload = buf[:cb]
    crc_ok = compute_crc(payload) == tr.dw_crc
    sig_ok = True
    if not crc_ok:
        # Without a CRC match the signature alone is weak; demand it at least.
        return None
    return CarvedBlock(ib=ib, bid=bid, cb=cb, crc_ok=crc_ok,
                       sig_ok=sig_ok, payload=payload)


def carve(reader: FileReader, variant: Variant, *,
          sink: Optional[WarningSink] = None,
          block_stride: int = 64) -> CarveResult:
    """Linear full-file carve for BBT/NBT pages and data blocks (PLAN §7.2).

    Args:
        reader: The store :class:`FileReader`.
        variant: Resolved store geometry (page/block sizes, trailer layout).
        sink: Optional warning sink (a fresh one is used if omitted).
        block_stride: Granularity for block-trailer probing (64 by default;
            4096 for the 4K-OST variant — Appendix A H20 / §8.7).

    Returns:
        A :class:`CarveResult` with carved BBT/NBT entries and data blocks.  The
        caller (:mod:`pstforensic.recovery.rebuild`) reconciles them into a
        rebuilt index.
    """
    sink = sink if sink is not None else WarningSink()
    size = reader.size
    result = CarveResult()

    page = variant.page_size
    if variant.page_size == 4096:
        block_stride = 4096

    # --- Pass 1: PAGETRAILER scan (BBT/NBT leaf recovery) ---
    # Pages are page_size bytes but sit on block-aligned (64B) offsets in real
    # and synthetic stores, not 512B-aligned — so probe every block_align slot
    # (4096 for 4K-OST per §8.7).  A validated trailer + counters disambiguates.
    page_stride = variant.block_align if variant.page_size != 4096 else 4096
    off = 0
    while off + page <= size:
        buf = reader.read(off, page)
        result.pages_scanned += 1
        ptype = _page_trailer_valid(buf, off, variant)
        if ptype is not None:
            result.page_candidates += 1
            entries, is_leaf = _carve_leaf_entries(buf, ptype, variant, size)
            if is_leaf:
                if ptype == PTYPE_BBT:
                    result.bbt_entries.extend(entries)
                else:
                    result.nbt_entries.extend(entries)
        off += page_stride

    # --- Pass 2: block-trailer scan over the whole file (data recovery) ---
    # Probe each ``block_stride``-aligned slot: read the candidate cb from the
    # would-be trailer and validate.  Because a block's footprint is
    # ceil((cb+trailer)/64)*64, a trailer always ends on a 64B boundary, so we
    # test every aligned end position.
    ts = variant.block_trailer_size
    pos = block_stride
    while pos <= size:
        # The trailer for a block ending at ``pos`` starts at ``pos - ts``.
        tr_off = pos - ts
        if tr_off < 0:
            pos += block_stride
            continue
        cb = reader.u16(tr_off)
        if 0 < cb <= variant.page_size * 512:
            disk = block_disk_size(cb, variant)
            ib = pos - disk
            if ib >= 0 and (ib % variant.block_align) == 0:
                cand = _block_trailer_valid(reader, ib, cb, variant)
                if cand is not None:
                    result.block_candidates += 1
                    result.blocks.append(cand)
        pos += block_stride

    return result
