"""Block resolution + XBLOCK/XXBLOCK data reassembly ([MS-PST] §2.2.2.8).

A *block* is ``cb`` bytes of payload followed by padding to a 64-byte multiple,
with the last ``variant.block_trailer_size`` bytes of the padded region holding
the BLOCKTRAILER ([MS-PST] §2.2.2.8.1):

  Unicode (16B): cb(2) wSig(2) dwCRC(4) bid(8)
  ANSI    (12B): cb(2) wSig(2) bid(4)  dwCRC(4)   (bid/dwCRC swapped vs Unicode)

On-disk footprint = ``ceil((cb + block_trailer_size) / 64) * 64``.

Data blocks (``bid`` internal bit clear) carry raw payload.  Internal blocks
(internal bit set) are XBLOCK (btype 0x01, cLevel 1) or XXBLOCK (cLevel 2)
which fan out to child block BIDs to reassemble a stream larger than one block
([MS-PST] §2.2.2.8.3.2).  Decode (NONE/PERMUTE/CYCLIC) is applied to **leaf
data blocks only**; XBLOCK metadata is never encrypted.
"""
from __future__ import annotations

import zlib
from typing import Optional
from dataclasses import dataclass

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from ..integrity import GUESSED, INFERRED, VERIFIED, BlockVerdict
from ..variant import Variant
from .bref import bid_is_internal, normalize_bid
from .btree import BBTEntry
import logging as _logging

_log = _logging.getLogger("pstforensic.block")
from .crc import compute_crc, compute_sig

BTYPE_XBLOCK = 0x01   # XBLOCK / XXBLOCK ([MS-PST] §2.2.2.8.3.2)
BTYPE_SUBNODE = 0x02  # SLBLOCK / SIBLOCK ([MS-PST] §2.2.2.8.3.3)


# bClientSig values of a real Heap-on-Node ([MS-PST] §2.3.1.2).
HN_CLIENT_SIGS = frozenset({0x6C, 0x7C, 0x8C, 0x9C, 0xA5, 0xAC, 0xB5, 0xBC})
_CRYPT_METHODS = (0, 1, 2)


def looks_like_heap(plain: bytes) -> bool:
    """True iff ``plain`` is the first block of a Heap-on-Node.

    HNHDR bSig 0xEC + known bClientSig + an HNPAGEMAP whose rgibAlloc starts
    right after the 12-byte HNHDR, never decreases and ends at or before
    ``ibHnpm``.  A wrongly decoded block passes this with negligible
    probability — the evidence the crypt ladder relies on (PLAN §14.4).
    """
    if len(plain) < 16 or plain[2] != 0xEC or plain[3] not in HN_CLIENT_SIGS:
        return False
    ib_hnpm = int.from_bytes(plain[0:2], "little")
    if ib_hnpm < 12 or ib_hnpm + 4 > len(plain):
        return False
    c_alloc = int.from_bytes(plain[ib_hnpm:ib_hnpm + 2], "little")
    end = ib_hnpm + 4 + 2 * (c_alloc + 1)
    if end > len(plain):
        return False
    prev = 12
    for k in range(c_alloc + 1):
        o = ib_hnpm + 4 + 2 * k
        v = int.from_bytes(plain[o:o + 2], "little")
        if (k == 0 and v != 12) or v < prev or v > ib_hnpm:
            return False
        prev = v
    return True


@dataclass
class BlockTrailer:
    """BLOCKTRAILER ([MS-PST] §2.2.2.8.1)."""

    cb: int
    w_sig: int
    dw_crc: int
    bid: int


def block_disk_size(cb: int, variant: Variant) -> int:
    """On-disk padded footprint of a block holding ``cb`` payload bytes.

    ([MS-PST] §2.2.2.8: payload + trailer rounded up to ``block_align`` (64)).
    """
    align = variant.block_align
    total = cb + variant.block_trailer_size
    return ((total + align - 1) // align) * align


def parse_block_trailer(buf: bytes, variant: Variant) -> BlockTrailer:
    """Parse the BLOCKTRAILER from the last ``block_trailer_size`` bytes of ``buf``."""
    t = buf[len(buf) - variant.block_trailer_size:]
    cb = int.from_bytes(t[0:2], "little")
    w_sig = int.from_bytes(t[2:4], "little")
    if variant.is_unicode:
        dw_crc = int.from_bytes(t[4:8], "little")
        bid = int.from_bytes(t[8:16], "little")
    else:  # ANSI: bid @ +4, dwCRC @ +8
        bid = int.from_bytes(t[4:8], "little")
        dw_crc = int.from_bytes(t[8:12], "little")
    return BlockTrailer(cb=cb, w_sig=w_sig, dw_crc=dw_crc, bid=bid)


class BlockReader:
    """Reads and reassembles blocks given a BBT index ``{bid: BBTEntry}``.

    Every read records a strict :class:`BlockVerdict` in :attr:`verdicts`.
    BIDs absent from the BBT (freed blocks of deleted items) are located via
    an attached scan locator (:meth:`attach_scan`) and flagged ``from_scan``.
    """

    def __init__(self, reader: FileReader, variant: Variant, *,
                 bbt: dict[int, BBTEntry], sink: WarningSink,
                 crypt_method: int = 0, max_depth: int = 32):
        self.reader = reader
        self.variant = variant
        self.bbt = bbt
        self.sink = sink
        self.crypt_method = crypt_method
        self.max_depth = max_depth
        self.verdicts: dict[int, BlockVerdict] = {}
        self._scan_locate = None  # Callable[[bid], Optional[(ib, cb)]]
        self.prefer: dict[int, tuple[int, int]] = {}  # recover(): alternate copies
        # Crypt ladder (PLAN §14.4): try every method on a stream's first
        # block, accept only on heap-structure evidence, learn the order.
        self.crypt_order = ([crypt_method] if crypt_method in _CRYPT_METHODS else []) + \
            [m for m in _CRYPT_METHODS if m != crypt_method]
        self.verified_counts = {m: 0 for m in _CRYPT_METHODS}
        # root bid -> (method, level), kept only when it deviates from the header
        # or is merely a guess (clean streams carry no findings).
        self.stream_crypt: dict[int, tuple[int, str]] = {}
        self._stream: list = [None, None]  # [method, level] of the stream being read

    def attach_scan(self, locate) -> None:
        """Use ``locate(bid) -> (ib, cb) | None`` for BIDs missing from the BBT."""
        self._scan_locate = locate

    def locate(self, bid: int) -> tuple[int, int, bool] | None:
        """Return ``(ib, cb, from_scan)`` for ``bid``, or ``None``."""
        alt = self.prefer.get(bid)
        if alt is not None:
            return alt[0], alt[1], True
        ent = self.bbt.get(bid)
        if ent is not None:
            return ent.bref.ib, ent.cb, False
        if self._scan_locate is not None:
            hit = self._scan_locate(bid)
            if hit is not None:
                return hit[0], hit[1], True
        return None

    # -- raw block bytes --------------------------------------------------
    def read_raw(self, bid: int) -> bytes | None:
        """Return the ``cb`` payload bytes of block ``bid`` (no decode).

        Never gates on CRC/signature: a mismatch is recorded in the block's
        verdict (and mirrored to the sink) and the data is still returned.
        """
        loc = self.locate(bid)
        where = f"bid={bid:#x}"
        if loc is None:
            self.verdicts[bid] = BlockVerdict(bid=bid, ib=None, missing=True)
            self.sink.warn(WarnCode.OUT_OF_BOUNDS, f"bid {bid:#x} not in BBT",
                           where=where)
            return None
        ib, cb, from_scan = loc
        disk = block_disk_size(cb, self.variant)
        buf = self.reader.read(ib, disk, where=f"block@{ib:#x}")
        complete = len(buf) >= disk
        if not complete:
            self.sink.warn(WarnCode.TRUNCATED, f"short block {len(buf)}/{disk}",
                           where=where)
            self.verdicts[bid] = BlockVerdict(bid=bid, ib=ib, complete=False,
                                              crc_ok=False, sig_ok=False,
                                              from_scan=from_scan)
            if len(buf) < cb:
                return buf[:cb] if buf else None
            return buf[:cb]
        payload = buf[:cb]
        tr = parse_block_trailer(buf, self.variant)
        cb_ok = tr.cb == cb
        bid_ok = normalize_bid(tr.bid) == bid
        if from_scan and not bid_ok:
            # Placed only by a stale index entry, and the trailer there names
            # another block: the bytes provably belong to someone else.  Using
            # them would attribute foreign content to this node.
            self.verdicts[bid] = BlockVerdict(bid=bid, ib=ib, missing=True)
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"bid {bid:#x}: location reused by bid {tr.bid:#x}",
                           where=where)
            return None
        crc_ok = compute_crc(payload) == tr.dw_crc
        sig_ok = compute_sig(ib, tr.bid) == tr.w_sig
        verdict = BlockVerdict(bid=bid, ib=ib, crc_ok=crc_ok, sig_ok=sig_ok,
                               bid_ok=bid_ok, cb_ok=cb_ok, from_scan=from_scan)
        if verdict.verified and not from_scan:
            # Clean blocks carry no findings: keep memory proportional to damage.
            self.verdicts.pop(bid, None)
        else:
            self.verdicts[bid] = verdict
        if not cb_ok:
            self.sink.warn(WarnCode.BLOCK_CRC_FAIL,
                           f"trailer cb {tr.cb} != BBT cb {cb}", where)
        if not bid_ok:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"trailer bid {tr.bid:#x} != {bid:#x}", where)
        if not crc_ok:
            self.sink.warn(WarnCode.BLOCK_CRC_FAIL, "block CRC mismatch", where)
        if not sig_ok:
            self.sink.warn(WarnCode.SIG_MISMATCH, "block wSig mismatch", where)
        return payload

    # -- decoded data stream ---------------------------------------------
    def read_data_stream(self, bid: int, touched: set[int] | None = None) -> bytes:
        """Resolve a node's data BID into its full decoded byte stream.

        Handles a single data block, or fans out an XBLOCK (cLevel 1) /
        XXBLOCK (cLevel 2) tree, concatenating child data blocks in order.
        Decode is applied to leaf data blocks only.  Depth- and cycle-guarded.
        Every BID read is added to ``touched`` (per-node integrity).
        """
        seen: set[int] = set()
        saved, self._stream = self._stream, [None, None]
        try:
            return self._read_data(bid, depth=0, seen=seen)
        finally:
            if self._stream[0] is not None and (
                    self._stream[0] != self.crypt_method or self._stream[1] == GUESSED):
                self.stream_crypt[bid] = (self._stream[0], self._stream[1])
            self._stream = saved
            if touched is not None:
                touched |= seen

    def _settled(self) -> bool:
        """Store-wide evidence: only the preferred method has ever verified."""
        first = self.crypt_order[0]
        return self.verified_counts[first] > 0 and not any(
            n for m, n in self.verified_counts.items() if m != first)

    def _decode_first(self, raw: bytes, bid: int) -> bytes:
        """Decode a stream's first leaf block via the crypt ladder."""
        from .crypt import decode_block
        for m in self.crypt_order:
            plain = decode_block(raw, m, bid)
            if looks_like_heap(plain):
                self.verified_counts[m] += 1
                if self.crypt_order[0] != m:
                    _log.info("crypt: bid %#x verifies as method %d (header %#x); "
                              "order now %s", bid, m, self.crypt_method,
                              [m] + [x for x in self.crypt_order if x != m])
                    self.crypt_order.remove(m)
                    self.crypt_order.insert(0, m)
                self._stream[:] = [m, VERIFIED]
                return plain
            if m == self.crypt_order[0] and self._settled():
                break   # unverifiable (non-heap) stream; store-wide evidence holds
        m = self.crypt_order[0]
        self._stream[:] = [m, INFERRED if self._settled() else GUESSED]
        if self._stream[1] == GUESSED:
            _log.debug("crypt: bid %#x not verifiable; guessing method %d", bid, m)
        return decode_block(raw, m, bid)

    def _read_data(self, bid: int, depth: int, seen: set[int]) -> bytes:
        if depth > self.max_depth:
            self.sink.warn(WarnCode.CYCLE_DETECTED, f"depth>{self.max_depth}",
                           where=f"bid={bid:#x}")
            return b""
        if bid in seen:
            self.sink.warn(WarnCode.CYCLE_DETECTED, "bid revisited",
                           where=f"bid={bid:#x}")
            return b""
        seen.add(bid)

        raw = self.read_raw(bid)
        if raw is None:
            return b""

        if not bid_is_internal(bid):
            # Leaf data block: maybe 4K-compressed, then decode.
            raw = self._maybe_inflate(raw, bid, self._inflated_size(bid, raw))
            if self._stream[0] is None:
                return self._decode_first(raw, bid)
            from .crypt import decode_block
            return decode_block(raw, self._stream[0], bid)

        # Internal block: XBLOCK (cLevel 1) or XXBLOCK (cLevel 2).
        if len(raw) < 8:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS, "internal block <8B",
                           where=f"bid={bid:#x}")
            return b""
        btype = raw[0]
        c_level = raw[1]
        c_ent = int.from_bytes(raw[2:4], "little")
        lcb_total = int.from_bytes(raw[4:8], "little")
        if btype != BTYPE_XBLOCK:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"btype {btype:#x} != XBLOCK on data path",
                           where=f"bid={bid:#x}")
        w = self.variant.bid_size
        out = bytearray()
        base = 8
        for i in range(c_ent):
            o = base + i * w
            child = normalize_bid(int.from_bytes(raw[o:o + w], "little"))
            out += self._read_data(child, depth + 1, seen)
        if lcb_total and len(out) != lcb_total:
            self.sink.warn(WarnCode.TRUNCATED,
                           f"reassembled {len(out)} != lcbTotal {lcb_total}",
                           where=f"bid={bid:#x}")
        return bytes(out)

    def _inflated_size(self, bid: int, raw: bytes) -> Optional[int]:
        """4K: cbInflated from the BBT entry, else from the block trailer."""
        if self.variant.page_size != 4096:
            return None
        ent = self.bbt.get(bid)
        if ent is not None and ent.cb_inflated is not None:
            return ent.cb_inflated
        loc = self.locate(bid)
        if loc is None:
            return None
        ib, cb, _ = loc
        disk = block_disk_size(cb, self.variant)
        tr = self.reader.read(ib + disk - self.variant.block_trailer_size,
                              self.variant.block_trailer_size)
        return int.from_bytes(tr[18:20], "little") if len(tr) >= 20 else None

    def _maybe_inflate(self, raw: bytes, bid: int, inflated: Optional[int]) -> bytes:
        """4K-OST: a block whose cbInflated differs from cb is zlib-deflated.

        On failure returns the raw bytes and warns ``COMPRESS_FAIL``.
        """
        if self.variant.page_size != 4096 or not inflated or inflated == len(raw):
            return raw
        try:
            out = zlib.decompress(raw)
        except zlib.error:
            self.sink.warn(WarnCode.COMPRESS_FAIL, "zlib.decompress failed",
                           where=f"bid={bid:#x}")
            return raw
        if len(out) != inflated:
            self.sink.warn(WarnCode.COMPRESS_FAIL,
                           f"inflated {len(out)} != cbInflated {inflated}",
                           where=f"bid={bid:#x}")
        return out
        if not self.variant.verified:
            self.sink.warn(WarnCode.UNVERIFIED_CONST,
                           "4K block compression order is a working hypothesis",
                           where=f"bid={bid:#x}")
        try:
            return zlib.decompress(raw)
        except zlib.error:
            self.sink.warn(WarnCode.COMPRESS_FAIL, "zlib.decompress failed",
                           where=f"bid={bid:#x}")
            return raw
