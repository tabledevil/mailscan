"""Generic BTPAGE walk for the NBT (ptype 0x81) and BBT (ptype 0x80).

[MS-PST] §2.2.2.7.7 (BTPAGE), §2.2.2.7.7.2 (BTENTRY), §2.2.2.7.7.3 (BBTENTRY),
§2.2.2.7.7.4 (NBTENTRY), §2.2.2.7.1 (PAGETRAILER).

A BTPAGE occupies a whole page (``variant.page_size``).  Entries fill from
offset 0; the bytes just before the PAGETRAILER hold the four counters
``cEnt`` / ``cEntMax`` / ``cbEnt`` / ``cLevel`` (one byte each), and on Unicode
a 4-byte ``dwPadding``.  The entry **stride is ``cbEnt`` from the page itself**,
never ``sizeof`` (a frequent quirk source — PLAN §4.2): real files pad entries.

Guards:
  * ``cEnt`` is clamped to what physically fits (``ENTRY_OVERFLOW``).
  * A visited-offset set prunes page cycles (``CYCLE_DETECTED``).
  * PAGETRAILER ``ptype``/``ptypeRepeat``/``wSig``/``dwCRC`` are advisory
    (warn, never abort).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from ..variant import Variant
from .bref import BREF, parse_bref
from .crc import compute_crc, compute_sig

# Page types ([MS-PST] §2.2.2.7.1).
PTYPE_BBT = 0x80   # Block BTree page
PTYPE_NBT = 0x81   # Node BTree page
PTYPE_FMAP = 0x82
PTYPE_PMAP = 0x83
PTYPE_AMAP = 0x84
PTYPE_FPMAP = 0x85
PTYPE_DL = 0x86    # Density List


@dataclass
class PageTrailer:
    """PAGETRAILER ([MS-PST] §2.2.2.7.1)."""

    ptype: int
    ptype_repeat: int
    w_sig: int
    dw_crc: int
    bid: int


@dataclass
class BBTEntry:
    """A leaf Block-BTree entry ([MS-PST] §2.2.2.7.7.3)."""

    bref: BREF
    cb: int       # number of raw bytes of the block (excludes trailer padding)
    c_ref: int    # reference count

    @property
    def bid(self) -> int:
        """Normalized BID (BBT lookup key)."""
        return self.bref.bid


@dataclass
class NBTEntry:
    """A leaf Node-BTree entry ([MS-PST] §2.2.2.7.7.4)."""

    nid: int
    bid_data: int   # normalized
    bid_sub: int    # normalized (0 if none)
    nid_parent: int


@dataclass
class BTEntry:
    """An intermediate BTree entry ([MS-PST] §2.2.2.7.7.2)."""

    btkey: int
    bref: BREF


def parse_page_trailer(page: bytes, variant: Variant) -> PageTrailer:
    """Parse the PAGETRAILER at the end of ``page`` ([MS-PST] §2.2.2.7.1).

    ANSI lays out ``bid`` before ``dwCRC``; Unicode/4K lay ``dwCRC`` before
    ``bid`` (the documented swap — encoded as data, not a code branch).
    """
    t = page[len(page) - variant.page_trailer_size:]
    ptype = t[0]
    ptype_repeat = t[1]
    w_sig = int.from_bytes(t[2:4], "little")
    if variant.is_unicode:
        dw_crc = int.from_bytes(t[4:8], "little")
        bid = int.from_bytes(t[8:16], "little")
    else:  # ANSI: bid @ +4, dwCRC @ +8
        bid = int.from_bytes(t[4:8], "little")
        dw_crc = int.from_bytes(t[8:12], "little")
    return PageTrailer(ptype, ptype_repeat, w_sig, dw_crc, bid)


def _page_counters(page: bytes, variant: Variant) -> tuple[int, int, int, int]:
    """Return (cEnt, cEntMax, cbEnt, cLevel) from a BTPAGE ([MS-PST] §2.2.2.7.7).

    The four 1-byte counters sit immediately before the PAGETRAILER, after a
    4-byte ``dwPadding`` on Unicode (no padding on ANSI).
    """
    pad = 4 if variant.is_unicode else 0
    base = len(page) - variant.page_trailer_size - pad - 4
    c_ent = page[base]
    c_ent_max = page[base + 1]
    cb_ent = page[base + 2]
    c_level = page[base + 3]
    return c_ent, c_ent_max, cb_ent, c_level


def entries_region_size(variant: Variant) -> int:
    """Bytes available for rgentries before counters+padding+trailer."""
    pad = 4 if variant.is_unicode else 0
    return variant.page_size - variant.page_trailer_size - pad - 4


def _parse_bbt_entry(buf: bytes, off: int, variant: Variant) -> BBTEntry:
    """[MS-PST] §2.2.2.7.7.3 — BREF(8/16) + cb(2) + cRef(2) [+ pad]."""
    bref = parse_bref(buf, off, variant.bid_size)
    p = off + variant.bref_size
    cb = int.from_bytes(buf[p:p + 2], "little")
    c_ref = int.from_bytes(buf[p + 2:p + 4], "little")
    return BBTEntry(bref=bref, cb=cb, c_ref=c_ref)


def _parse_nbt_entry(buf: bytes, off: int, variant: Variant) -> NBTEntry:
    """[MS-PST] §2.2.2.7.7.4.

    Unicode: nid(8: 4 used +4 pad), bidData(8), bidSub(8), nidParent(4), pad(4).
    ANSI:    nid(4), bidData(4), bidSub(4), nidParent(4).
    """
    w = variant.bid_size
    if variant.is_unicode:
        nid = int.from_bytes(buf[off:off + 4], "little")  # low 4 of the 8
        bid_data = int.from_bytes(buf[off + 8:off + 16], "little")
        bid_sub = int.from_bytes(buf[off + 16:off + 24], "little")
        nid_parent = int.from_bytes(buf[off + 24:off + 28], "little")
    else:
        nid = int.from_bytes(buf[off:off + 4], "little")
        bid_data = int.from_bytes(buf[off + w:off + 2 * w], "little")
        bid_sub = int.from_bytes(buf[off + 2 * w:off + 3 * w], "little")
        nid_parent = int.from_bytes(buf[off + 3 * w:off + 4 * w], "little")
    from .bref import normalize_bid
    return NBTEntry(
        nid=nid,
        bid_data=normalize_bid(bid_data),
        bid_sub=normalize_bid(bid_sub),
        nid_parent=nid_parent,
    )


def _parse_bt_entry(buf: bytes, off: int, variant: Variant) -> BTEntry:
    """[MS-PST] §2.2.2.7.7.2 — btkey(4/8) + BREF(8/16)."""
    w = variant.bid_size
    btkey = int.from_bytes(buf[off:off + w], "little")
    bref = parse_bref(buf, off + w, variant.bid_size)
    return BTEntry(btkey=btkey, bref=bref)


def _verify_trailer(reader: FileReader, page: bytes, ib: int, expected_ptype: int,
                    variant: Variant, sink: WarningSink) -> PageTrailer:
    tr = parse_page_trailer(page, variant)
    where = f"page@{ib:#x}"
    if tr.ptype != tr.ptype_repeat:
        sink.warn(WarnCode.SIG_MISMATCH,
                  f"ptype {tr.ptype:#x} != ptypeRepeat {tr.ptype_repeat:#x}", where)
    if tr.ptype != expected_ptype:
        sink.warn(WarnCode.SIG_MISMATCH,
                  f"ptype {tr.ptype:#x} != expected {expected_ptype:#x}", where)
    # Advisory CRC: covers the page bytes before the dwCRC/bid section
    # ([MS-PST] §2.2.2.7.1: CRC of the page data excluding the trailer's
    # dwCRC/bid).  We compute over the first (page_size - trailer) bytes.
    body = page[:variant.page_size - variant.page_trailer_size]
    calc = compute_crc(body)
    if calc != tr.dw_crc:
        sink.warn(WarnCode.PAGE_CRC_FAIL,
                  f"page CRC stored={tr.dw_crc:#010x} calc={calc:#010x}", where)
    sig = compute_sig(ib, tr.bid)
    if sig != tr.w_sig:
        sink.warn(WarnCode.SIG_MISMATCH,
                  f"wSig stored={tr.w_sig:#06x} calc={sig:#06x}", where)
    return tr


class BTreeWalker:
    """Walks an NBT or BBT B-tree and yields leaf entries.

    ``key_kind`` selects the leaf parser: ``"NID"`` (NBT, expected ptype 0x81)
    or ``"BID"`` (BBT, expected ptype 0x80).
    """

    def __init__(self, reader: FileReader, variant: Variant, *,
                 sink: WarningSink, max_depth: int = 64):
        self.reader = reader
        self.variant = variant
        self.sink = sink
        self.max_depth = max_depth

    def walk(self, root_bref: BREF, *, key_kind: str) -> Iterator:
        """Yield all leaf entries reachable from ``root_bref`` (depth-first)."""
        expected_ptype = PTYPE_NBT if key_kind == "NID" else PTYPE_BBT
        visited: set[int] = set()
        yield from self._walk_page(root_bref, key_kind, expected_ptype,
                                   visited, depth=0)

    def _walk_page(self, bref: BREF, key_kind: str, expected_ptype: int,
                   visited: set[int], depth: int) -> Iterator:
        if depth > self.max_depth:
            self.sink.warn(WarnCode.CYCLE_DETECTED,
                           f"depth>{self.max_depth}", f"page@{bref.ib:#x}")
            return
        if bref.ib in visited:
            self.sink.warn(WarnCode.CYCLE_DETECTED, "page revisited",
                           f"page@{bref.ib:#x}")
            return
        visited.add(bref.ib)

        page = self.reader.read(bref.ib, self.variant.page_size,
                                where=f"btpage@{bref.ib:#x}")
        if len(page) < self.variant.page_size:
            self.sink.warn(WarnCode.TRUNCATED,
                           f"short page {len(page)}/{self.variant.page_size}",
                           f"page@{bref.ib:#x}")
            return

        _verify_trailer(self.reader, page, bref.ib, expected_ptype,
                        self.variant, self.sink)

        c_ent, c_ent_max, cb_ent, c_level = _page_counters(page, self.variant)
        region = entries_region_size(self.variant)

        # Bounds guard: stride by cbEnt, clamp cEnt to what fits.
        if cb_ent == 0:
            self.sink.warn(WarnCode.ENTRY_OVERFLOW, "cbEnt==0",
                           f"page@{bref.ib:#x}")
            return
        max_fit = region // cb_ent
        if c_ent > max_fit:
            self.sink.warn(WarnCode.ENTRY_OVERFLOW,
                           f"cEnt {c_ent} > fits {max_fit}", f"page@{bref.ib:#x}")
            c_ent = max_fit

        for i in range(c_ent):
            off = i * cb_ent
            if c_level > 0:
                ent = _parse_bt_entry(page, off, self.variant)
                child = ent.bref
                if not (0 <= child.ib < self.reader.size):
                    self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                                   f"child ib {child.ib:#x} OOB",
                                   f"page@{bref.ib:#x}")
                    continue
                yield from self._walk_page(child, key_kind, expected_ptype,
                                           visited, depth + 1)
            else:
                if key_kind == "NID":
                    yield _parse_nbt_entry(page, off, self.variant)
                else:
                    yield _parse_bbt_entry(page, off, self.variant)
