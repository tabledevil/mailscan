"""Always-on full-file scan — the Kernel-parity harvest (PLAN §14.5).

One linear pass over the whole file, independent of the B-tree:

  * **Pages** (NBT 0x81 / BBT 0x80) on every 512-byte boundary (64 in a deep
    scan) for the 512-byte variants and every 4096-byte boundary for 4K, under
    the variants asked for (the store's own when its header proves it).  A
    page is accepted on Kernel's gate — ``ptype == ptypeRepeat`` plus the exact
    ``cEntMax``/``cbEnt`` geometry — and its CRC/signature are recorded.  Leaf
    slots are read **up to capacity**; slots at or beyond ``cEnt`` are tagged
    ``beyond_cent`` (deleted-entry residue).
  * **Blocks** from BLOCKTRAILERs at every 64-byte block end, under every
    512-byte variant: ``0 < cb <= 8192``, accepted when the signature matches,
    or when the CRC matches for a BID some harvested node wants.

Only material that *differs* from the live index is kept (memory stays
proportional to deleted/stale data, not file size): NBT slots identical to a
live entry are only counted; blocks sitting exactly where the live BBT says
are only kept as extents for false-positive suppression.

False-positive suppression (PLAN §14.7): a page or block whose trailer lies
inside a verified block's extent is attachment payload (e.g. a PST attached to
a mail), not structure, and is discarded.

numpy is used when available; the pure-Python path produces identical output.
"""
from __future__ import annotations

import bisect
import struct
import zlib
from dataclasses import dataclass, field
from typing import Callable, Optional

from ..fileio import FileReader
from ..variant import ANSI, UNICODE, UNICODE_4K, Variant
from .block import block_disk_size
from .bref import BREF, normalize_bid, nid_type
from .btree import (
    PTYPE_BBT,
    PTYPE_NBT,
    BBTEntry,
    NBTEntry,
    _page_counters,
    _parse_bbt_entry,
    _parse_nbt_entry,
    expected_geometry,
    parse_page_trailer,
)

try:  # optional fast path
    import numpy as _np
except ImportError:  # pragma: no cover - exercised via use_numpy=False
    _np = None

MAX_BLOCK_CB = 8192
# NID types worth harvesting: internal (store PC 0x21, name map 0x61), folders,
# search folders, messages, FAI messages and the folder tables — enough to
# rebuild a store whose NBT root or inner pages are destroyed.
HARVEST_NID_TYPES = frozenset({0x01, 0x02, 0x03, 0x04, 0x08, 0x0D, 0x0E, 0x0F})
CHUNK = 64 * 1024 * 1024


def _crc(data) -> int:
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def _sig(ib: int, bid: int) -> int:
    x = (ib ^ bid) & 0xFFFFFFFF
    return ((x >> 16) ^ x) & 0xFFFF


@dataclass(slots=True)
class ScannedPage:
    ib: int
    variant: str
    ptype: int
    bid: int
    c_ent: int
    c_level: int
    crc_ok: bool
    sig_ok: bool
    is_live: bool = False   # this page is part of the live B-tree

    @property
    def aligned512(self) -> bool:
        return self.ib % 512 == 0


@dataclass(slots=True)
class ScannedSlot:
    """An NBT leaf entry harvested by the scan that differs from the live NBT."""

    entry: NBTEntry
    variant: str
    beyond_cent: bool
    page_bid: int           # trailer BID of the page: higher = newer copy
    page_live: bool         # the page it sits in is a live B-tree page
    page_crc_ok: bool
    page_sig_ok: bool


@dataclass(slots=True)
class ScannedBlock:
    ib: int
    bid: int
    raw_bid: int
    cb: int
    variant: str
    crc_ok: bool
    sig_ok: bool

    @property
    def strong(self) -> bool:
        return self.crc_ok and self.sig_ok


@dataclass
class ScanStats:
    bytes_scanned: int = 0
    pages_seen: int = 0
    pages_suppressed: int = 0
    live_duplicate_slots: int = 0
    empty_slots: int = 0
    block_candidates: int = 0
    blocks_live: int = 0
    blocks_dropped_weak: int = 0
    blocks_suppressed: int = 0
    foreign_variant_pages: int = 0


@dataclass
class ScanIndex:
    """Everything the scan harvested beyond the live index."""

    file_size: int
    store_variant: str
    complete: bool = True
    pages: list[ScannedPage] = field(default_factory=list)
    slots: list[ScannedSlot] = field(default_factory=list)
    bbt_entries: list[BBTEntry] = field(default_factory=list)  # non-live, from scanned BBT pages
    blocks: dict[int, list[ScannedBlock]] = field(default_factory=dict)
    stats: ScanStats = field(default_factory=ScanStats)
    _bbt_by_bid: Optional[dict] = field(default=None, repr=False)

    def locate(self, bid: int) -> Optional[tuple[int, int]]:
        """Best on-disk copy of ``bid``: strong › sig › CRC › scanned BBT entry."""
        cands = self.blocks.get(bid)
        if cands:
            best = min(cands, key=lambda b: (not b.strong, not b.sig_ok, not b.crc_ok))
            return best.ib, best.cb
        if self._bbt_by_bid is None:
            self._bbt_by_bid = {}
            for ent in self.bbt_entries:
                self._bbt_by_bid.setdefault(ent.bid, ent)
        ent = self._bbt_by_bid.get(bid)
        return (ent.bref.ib, ent.cb) if ent is not None else None

    def copies(self, bid: int) -> list[ScannedBlock]:
        return list(self.blocks.get(bid, ()))


# ---------------------------------------------------------------------------
# Candidate generation (numpy and pure-Python, identical results)
# ---------------------------------------------------------------------------
def _page_candidates(mv, base: int, n: int, size: int, v: Variant, stride: int,
                     use_np: bool) -> list[int]:
    """Page start offsets in ``[base, base+n)`` passing the ptype gate."""
    page, ts = v.page_size, v.page_trailer_size
    t_off = page - ts
    first = -(-base // stride) * stride
    last = min(base + n, size - page + 1)
    if last <= first:
        return []
    if use_np:
        ibs = _np.arange(first, last, stride, dtype=_np.int64)
        arr = _np.frombuffer(mv, dtype=_np.uint8)
        pt = arr[ibs + t_off]
        ok = (pt == PTYPE_NBT) | (pt == PTYPE_BBT)
        if not v.wide_page_counters:
            ok &= pt == arr[ibs + t_off + 1]
        return ibs[ok].tolist()
    out = []
    for ib in range(first, last, stride):
        p = mv[ib + t_off]
        if p in (PTYPE_NBT, PTYPE_BBT) and (v.wide_page_counters or mv[ib + t_off + 1] == p):
            out.append(ib)
    return out


_TRAILER_FMT = {"ansi": "<HHII", "unicode": "<HHIQ"}  # cb wSig (bid crc)|(crc bid)


def _block_candidates(mv, base: int, n: int, size: int, v: Variant,
                      wanted: set[int], wanted_arr, use_np: bool):
    """Yield ``(ib, cb, w_sig, crc, raw_bid, sig_ok)`` for plausible block ends."""
    ts = v.block_trailer_size
    first = base + 64          # block ends in (base, base + n]; base % 64 == 0
    last = min(base + n, size)
    if last < first:
        return
    if use_np:
        ends = _np.arange(first, last + 1, 64, dtype=_np.int64)
        arr = _np.frombuffer(mv, dtype=_np.uint8)
        tr = arr[(ends - ts)[:, None] + _np.arange(ts)[None, :]]
        tr = _np.ascontiguousarray(tr)
        cb = tr[:, 0:2].copy().view("<u2")[:, 0].astype(_np.int64)
        wsig = tr[:, 2:4].copy().view("<u2")[:, 0].astype(_np.int64)
        if v.is_unicode:
            crc = tr[:, 4:8].copy().view("<u4")[:, 0].astype(_np.int64)
            rbid = tr[:, 8:16].copy().view("<u8")[:, 0]
        else:
            rbid = tr[:, 4:8].copy().view("<u4")[:, 0].astype(_np.uint64)
            crc = tr[:, 8:12].copy().view("<u4")[:, 0].astype(_np.int64)
        disk = ((cb + ts + 63) // 64) * 64
        ib = ends - disk
        ok = (cb > 0) & (cb <= MAX_BLOCK_CB) & (ib >= 0)
        x = (ib.astype(_np.uint64) ^ rbid) & _np.uint64(0xFFFFFFFF)
        sig = ((x >> _np.uint64(16)) ^ x) & _np.uint64(0xFFFF)
        sig_ok = sig.astype(_np.int64) == wsig
        keep = ok & sig_ok
        if wanted_arr is not None and len(wanted_arr):
            nbid = rbid & ~_np.uint64(1)
            keep |= ok & _np.isin(nbid, wanted_arr)
        for i in _np.nonzero(keep)[0].tolist():
            yield (int(ib[i]), int(cb[i]), int(wsig[i]), int(crc[i]),
                   int(rbid[i]), bool(sig_ok[i]))
        return
    fmt = _TRAILER_FMT["unicode" if v.is_unicode else "ansi"]
    for end in range(first, last + 1, 64):
        if v.is_unicode:
            cb, wsig, crc, rbid = struct.unpack_from(fmt, mv, end - ts)
        else:
            cb, wsig, rbid, crc = struct.unpack_from(fmt, mv, end - ts)
        if not (0 < cb <= MAX_BLOCK_CB):
            continue
        ib = end - ((cb + ts + 63) // 64) * 64
        if ib < 0:
            continue
        sig_ok = _sig(ib, rbid) == wsig
        if sig_ok or normalize_bid(rbid) in wanted:
            yield ib, cb, wsig, crc, rbid, sig_ok


def _block_candidates_4k(mv, base: int, n: int, size: int, wanted: set[int],
                         wanted_arr, use_np: bool):
    """4K-OST block trailers (layout as in Kernel PST Viewer's scanner).

    Each 512-byte unit may end a block: its last 24 bytes, at +0x1E8, are the
    BLOCKTRAILER cb(2) wSig(2) dwCRC(4) bid(8) + 8; the block starts
    ``roundup512(cb + 24)`` before the unit's end (verified on a real OST).
    """
    first = base
    last = min(base + n, size - 512 + 1)
    if last <= first:
        return
    if use_np:
        units = _np.arange(first, last, 512, dtype=_np.int64)
        arr = _np.frombuffer(mv, dtype=_np.uint8)
        tr = _np.ascontiguousarray(arr[(units + 0x1E8)[:, None] + _np.arange(16)[None, :]])
        cb = tr[:, 0:2].copy().view("<u2")[:, 0].astype(_np.int64)
        wsig = tr[:, 2:4].copy().view("<u2")[:, 0].astype(_np.int64)
        crc = tr[:, 4:8].copy().view("<u4")[:, 0].astype(_np.int64)
        rbid = tr[:, 8:16].copy().view("<u8")[:, 0]
        ib = units + 512 - ((cb + 24 + 511) // 512) * 512
        ok = (cb > 0) & (rbid > 0) & (ib >= 0)
        x = (ib.astype(_np.uint64) ^ rbid) & _np.uint64(0xFFFFFFFF)
        sig_ok = (((x >> _np.uint64(16)) ^ x) & _np.uint64(0xFFFF)).astype(_np.int64) == wsig
        keep = ok & sig_ok
        if wanted_arr is not None and len(wanted_arr):
            keep |= ok & _np.isin(rbid & ~_np.uint64(1), wanted_arr)
        for i in _np.nonzero(keep)[0].tolist():
            yield (int(ib[i]), int(cb[i]), int(wsig[i]), int(crc[i]),
                   int(rbid[i]), bool(sig_ok[i]))
        return
    for unit in range(first, last, 512):
        cb, wsig, crc, rbid = struct.unpack_from("<HHIQ", mv, unit + 0x1E8)
        ib = unit + 512 - ((cb + 24 + 511) // 512) * 512
        if cb == 0 or rbid == 0 or ib < 0:
            continue
        sig_ok = _sig(ib, rbid) == wsig
        if sig_ok or normalize_bid(rbid) in wanted:
            yield ib, cb, wsig, crc, rbid, sig_ok


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------
class _Extents:
    """``[start, end)`` extents of blocks (each at most ~8.3 KB) with point queries."""

    _MAX_LEN = 0x10000 + 512   # 4K blocks: cb is a u16

    def __init__(self, spans):
        spans = sorted(spans)
        self.starts = [s for s, _ in spans]
        self.ends = [e for _, e in spans]

    def containing(self, pos: int) -> Optional[tuple[int, int]]:
        i = bisect.bisect_right(self.starts, pos) - 1
        while i >= 0 and self.starts[i] > pos - self._MAX_LEN:
            if pos < self.ends[i]:
                return self.starts[i], self.ends[i]
            i -= 1
        return None


# ---------------------------------------------------------------------------
# Range workers — the scan runs over independent byte ranges, serially or in
# a process pool (fork: workers inherit the mapping and the live index).
# ---------------------------------------------------------------------------
@dataclass
class _Ctx:
    mv: object
    size: int
    variants: tuple
    store_variant: Variant
    live_nbt: dict
    live_bbt: dict
    live_page_ibs: set
    wanted: set
    use_np: bool
    page_stride: int
    wanted_arr: object = None


_CTX: Optional[_Ctx] = None     # set before forking a pool


def _pages_range(ctx: _Ctx, base: int, n: int):
    part = ScanIndex(file_size=ctx.size, store_variant=ctx.store_variant.name)
    wanted: set[int] = set()
    for v in ctx.variants:
        stride = 4096 if v.page_size == 4096 else ctx.page_stride
        for ib in _page_candidates(ctx.mv, base, n, ctx.size, v, stride, ctx.use_np):
            _take_page(part, ctx.mv, ib, v, ctx.store_variant, ctx.live_nbt,
                       ctx.live_bbt, ctx.live_page_ibs, wanted)
    return part.pages, part.slots, part.bbt_entries, part.stats, wanted


def _blocks_range(ctx: _Ctx, base: int, n: int):
    st = ScanStats()
    live_extents: list[tuple[int, int]] = []
    pending: list[ScannedBlock] = []
    mv, size = ctx.mv, ctx.size
    for v in (ANSI, UNICODE, UNICODE_4K):
        if v not in ctx.variants:
            continue
        if v is UNICODE_4K:
            cands = _block_candidates_4k(mv, base, n, size, ctx.wanted, ctx.wanted_arr,
                                         ctx.use_np)
        else:
            cands = _block_candidates(mv, base, n, size, v, ctx.wanted, ctx.wanted_arr,
                                      ctx.use_np)
        for ib, cb, _wsig, crc, rbid, sig_ok in cands:
            if ib + cb > size:
                continue
            st.block_candidates += 1
            bid = normalize_bid(rbid)
            live = ctx.live_bbt.get(bid)
            if v is ctx.store_variant and live is not None and live.bref.ib == ib and sig_ok:
                # Exactly where the live BBT says: only an extent.
                st.blocks_live += 1
                live_extents.append((ib, ib + _disk(cb, v)))
                continue
            crc_ok = _crc(mv[ib:ib + cb]) == crc
            if not (sig_ok or crc_ok):
                st.blocks_dropped_weak += 1
                continue
            pending.append(ScannedBlock(ib=ib, bid=bid, raw_bid=rbid, cb=cb,
                                        variant=v.name, crc_ok=crc_ok, sig_ok=sig_ok))
    return pending, live_extents, st


def _w_pages(rng):
    return _pages_range(_CTX, *rng)


def _w_blocks(rng):
    return _blocks_range(_CTX, *rng)


def _add_stats(into: ScanStats, part: ScanStats) -> None:
    for k, v in part.__dict__.items():
        if k != "bytes_scanned":
            setattr(into, k, getattr(into, k) + v)


def default_workers(size: int) -> int:
    """Worker processes for a file of ``size`` bytes: all cores for multi-GB
    stores on platforms with ``fork``; 1 otherwise (and below 512 MiB)."""
    import multiprocessing as mp
    import os
    if size < (512 << 20) or "fork" not in mp.get_all_start_methods():
        return 1
    return max(1, min(os.cpu_count() or 1, 32))


def _run(fn_local, fn_worker, ranges, workers, on_done, aborted):
    """Yield results in range order; ``on_done(end)`` after each range."""
    if workers <= 1 or len(ranges) <= 1:
        for base, n in ranges:
            if aborted():
                return
            yield fn_local(base, n)
            on_done(base + n)
        return
    import multiprocessing as mp
    with mp.get_context("fork").Pool(workers) as pool:
        for (base, n), res in zip(ranges, pool.imap(fn_worker, ranges)):
            if aborted():
                pool.terminate()
                return
            yield res
            on_done(base + n)


def scan_file(reader: FileReader, store_variant: Variant, *,
              live_nbt: Optional[dict] = None, live_bbt: Optional[dict] = None,
              live_page_ibs: Optional[set[int]] = None,
              variants: tuple[Variant, ...] = (ANSI, UNICODE, UNICODE_4K),
              use_numpy: Optional[bool] = None,
              progress: Optional[Callable[[int, int], None]] = None,
              should_abort: Optional[Callable[[], bool]] = None,
              page_stride: int = 512, workers: Optional[int] = None,
              chunk: int = CHUNK) -> ScanIndex:
    """Scan the whole file and return a :class:`ScanIndex` (PLAN §14.5).

    ``live_nbt`` / ``live_bbt`` (``{nid: NBTEntry}`` / ``{bid: BBTEntry}``) let
    the scan keep only what differs from the live index.  ``page_stride`` is
    512 (pages are 512-aligned, as Kernel assumes) or 64 for a deep scan of
    shifted copies.  ``workers`` > 1 scans byte ranges in parallel processes
    (results identical to the serial scan, in the same order).
    """
    global _CTX
    use_np = (_np is not None) if use_numpy is None else (use_numpy and _np is not None)
    live_nbt = live_nbt or {}
    live_bbt = live_bbt or {}
    live_page_ibs = live_page_ibs or set()
    size = reader.size
    idx = ScanIndex(file_size=size, store_variant=store_variant.name)
    st = idx.stats
    if workers is None:
        workers = default_workers(size)
    ranges = [(b, min(chunk, size - b)) for b in range(0, size, chunk)]

    def aborted() -> bool:
        if should_abort is not None and should_abort():
            idx.complete = False
            return True
        return False

    # BIDs some node needs but the live BBT cannot place (a damaged BBT
    # subtree): their blocks are located from trailers even on a weak sig.
    wanted: set[int] = {b for ent in live_nbt.values()
                        for b in (ent.bid_data, ent.bid_sub)
                        if b and b not in live_bbt}
    ctx = _Ctx(mv=reader._data, size=size, variants=tuple(variants),
               store_variant=store_variant, live_nbt=live_nbt, live_bbt=live_bbt,
               live_page_ibs=live_page_ibs, wanted=wanted, use_np=use_np,
               page_stride=page_stride)
    _CTX = ctx
    try:
        # ---- Phase 1: pages --------------------------------------------
        def pages_done(end: int) -> None:
            st.bytes_scanned = end
            if progress is not None:
                progress(end, 2 * size)

        for pages, slots, bbt_entries, pst, w in _run(
                lambda b, n: _pages_range(ctx, b, n), _w_pages, ranges, workers,
                pages_done, aborted):
            idx.pages += pages
            idx.slots += slots
            idx.bbt_entries += bbt_entries
            _add_stats(st, pst)
            wanted |= w
        if not idx.complete:
            return idx

        # ---- Phase 2: blocks -------------------------------------------
        ctx.wanted_arr = (_np.array(sorted(wanted), dtype=_np.uint64)
                          if (use_np and wanted) else None)
        live_extents: list[tuple[int, int]] = []
        pending: list[ScannedBlock] = []

        def blocks_done(end: int) -> None:
            if progress is not None:
                progress(size + end, 2 * size)

        for pend, ext, bst in _run(lambda b, n: _blocks_range(ctx, b, n), _w_blocks,
                                   ranges, workers, blocks_done, aborted):
            pending += pend
            live_extents += ext
            _add_stats(st, bst)
        if not idx.complete:
            return idx
    finally:
        _CTX = None

    # ---- Suppression: hits inside verified block extents ----------------
    live_x = _Extents(live_extents)
    strong = [b for b in pending if b.strong and live_x.containing(b.ib + 1) is None]
    strong_x = _Extents([(b.ib, b.ib + _disk(b.cb, _variant(b.variant)))
                         for b in strong])

    def inside(pos: int, own_start: Optional[int] = None) -> bool:
        if live_x.containing(pos) is not None:
            return True
        hit = strong_x.containing(pos)
        return hit is not None and hit[0] != own_start

    for b in pending:
        tr_pos = b.ib + _disk(b.cb, _variant(b.variant)) - 1
        if inside(b.ib, own_start=b.ib) or inside(tr_pos, own_start=b.ib):
            st.blocks_suppressed += 1
            continue
        idx.blocks.setdefault(b.bid, []).append(b)

    kept_pages = []
    suppressed_page_ibs = set()
    for p in idx.pages:
        v = _variant(p.variant)
        if not p.is_live and inside(p.ib + v.page_size - v.page_trailer_size):
            st.pages_suppressed += 1
            suppressed_page_ibs.add(p.ib)
            continue
        kept_pages.append(p)
    idx.pages = kept_pages
    if suppressed_page_ibs:
        idx.slots = [s for s in idx.slots if s.entry.page_ib not in suppressed_page_ibs]
        idx.bbt_entries = [e for e in idx.bbt_entries if e.page_ib not in suppressed_page_ibs]
    return idx


_BY_NAME = {v.name: v for v in (ANSI, UNICODE, UNICODE_4K)}


def _disk(cb: int, v: Variant) -> int:
    """On-disk footprint of a block."""
    return block_disk_size(cb, v)


def _variant(name: str) -> Variant:
    return _BY_NAME[name]


def _take_page(idx: ScanIndex, mv, ib: int, v: Variant, store_variant: Variant,
               live_nbt: dict, live_bbt: dict, live_page_ibs: set[int],
               wanted: set[int]) -> None:
    """Validate one page candidate (Kernel gate) and harvest its leaf slots."""
    page = bytes(mv[ib:ib + v.page_size])
    tr = parse_page_trailer(page, v)
    c_ent, c_ent_max, cb_ent, c_level = _page_counters(page, v)
    if (c_ent_max, cb_ent) != expected_geometry(v, tr.ptype, c_level) or c_ent > c_ent_max:
        return
    st = idx.stats
    st.pages_seen += 1
    if v is not store_variant:
        st.foreign_variant_pages += 1
    crc_ok = _crc(page[:v.page_size - v.page_trailer_size]) == tr.dw_crc
    sig_ok = _sig(ib, tr.bid) == tr.w_sig
    is_live = v is store_variant and ib in live_page_ibs
    idx.pages.append(ScannedPage(ib=ib, variant=v.name, ptype=tr.ptype, bid=tr.bid,
                                 c_ent=c_ent, c_level=c_level, crc_ok=crc_ok,
                                 sig_ok=sig_ok, is_live=is_live))
    if c_level != 0:
        return
    for slot in range(c_ent_max):
        off = slot * cb_ent
        if tr.ptype == PTYPE_NBT:
            ent = _parse_nbt_entry(page, off, v)
            if ent.nid == 0 and ent.bid_data == 0:
                st.empty_slots += 1
                continue
            if nid_type(ent.nid) not in HARVEST_NID_TYPES:
                continue
            ent.page_ib, ent.slot = ib, slot
            live = live_nbt.get(ent.nid)
            if (v is store_variant and live is not None
                    and (live.bid_data, live.bid_sub, live.nid_parent)
                    == (ent.bid_data, ent.bid_sub, ent.nid_parent)):
                st.live_duplicate_slots += 1
                continue
            idx.slots.append(ScannedSlot(entry=ent, variant=v.name,
                                         beyond_cent=slot >= c_ent, page_bid=tr.bid,
                                         page_live=is_live,
                                         page_crc_ok=crc_ok, page_sig_ok=sig_ok))
            if v is store_variant:
                for b in (ent.bid_data, ent.bid_sub):
                    if b and b not in live_bbt:
                        wanted.add(b)
        else:
            ent = _parse_bbt_entry(page, off, v)
            if ent.bid == 0 or ent.cb == 0:
                st.empty_slots += 1
                continue
            live = live_bbt.get(ent.bid)
            if v is store_variant and live is not None and live.bref.ib == ent.bref.ib:
                continue
            ent.page_ib = ib
            if v is store_variant:
                idx.bbt_entries.append(ent)
