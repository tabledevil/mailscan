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
from dataclasses import dataclass

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from ..integrity import BlockVerdict
from ..variant import Variant
from .bref import bid_is_internal, normalize_bid
from .btree import BBTEntry
from .crc import compute_crc, compute_sig

BTYPE_XBLOCK = 0x01   # XBLOCK / XXBLOCK ([MS-PST] §2.2.2.8.3.2)
BTYPE_SUBNODE = 0x02  # SLBLOCK / SIBLOCK ([MS-PST] §2.2.2.8.3.3)


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

    def attach_scan(self, locate) -> None:
        """Use ``locate(bid) -> (ib, cb) | None`` for BIDs missing from the BBT."""
        self._scan_locate = locate

    def locate(self, bid: int) -> tuple[int, int, bool] | None:
        """Return ``(ib, cb, from_scan)`` for ``bid``, or ``None``."""
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
        crc_ok = compute_crc(payload) == tr.dw_crc
        sig_ok = compute_sig(ib, tr.bid) == tr.w_sig
        self.verdicts[bid] = BlockVerdict(bid=bid, ib=ib, crc_ok=crc_ok,
                                          sig_ok=sig_ok, bid_ok=bid_ok,
                                          cb_ok=cb_ok, from_scan=from_scan)
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
        try:
            return self._read_data(bid, depth=0, seen=seen)
        finally:
            if touched is not None:
                touched |= seen

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
            raw = self._maybe_inflate(raw, bid)
            from .crypt import decode_block
            return decode_block(raw, self.crypt_method, bid)

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

    def _maybe_inflate(self, raw: bytes, bid: int) -> bytes:
        """4K-OST: blocks may be zlib-deflated (Appendix A H20, UNVERIFIED).

        Only attempted for the 4K variant; on failure, returns raw bytes and
        warns ``COMPRESS_FAIL`` (never aborts).
        """
        if self.variant.page_size != 4096:
            return raw
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
