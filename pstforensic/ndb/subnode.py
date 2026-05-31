"""Subnode (local-NID) block trees ([MS-PST] §2.2.2.8.3.3).

A node's ``bidSub`` roots a tree of *internal* blocks (``btype 0x02``) that map
**local** node-ids to their data/sub BIDs.  These are blocks identified by
``btype``/``cLevel`` — NOT page ptypes (Appendix A H7/H22):

  SLBLOCK (leaf, cLevel 0, [MS-PST] §2.2.2.8.3.3.1):
      btype(1)=0x02 cLevel(1)=0 cEnt(2) [dwPadding(4) Unicode]
      rgentries[]: SLENTRY = nid(8/4) bidData(8/4) bidSub(8/4)
  SIBLOCK (intermediate, cLevel 1, [MS-PST] §2.2.2.8.3.3.2):
      btype(1)=0x02 cLevel(1)=1 cEnt(2) [dwPadding(4) Unicode]
      rgentries[]: SIENTRY = nid(8/4) bid(8/4)  (child SLBLOCK/SIBLOCK)

``iter_subnodes(bidSub)`` yields ``(internal_nid, bidData, bidSub)`` leaves —
the source of message recipient/attachment TCs and embedded-message PCs.
"""
from __future__ import annotations

from typing import Iterator

from ..exceptions import WarnCode, WarningSink
from ..variant import Variant
from .block import BlockReader
from .bref import normalize_bid

SUBNODE_BTYPE = 0x02


class SubnodeReader:
    """Walks the SLBLOCK/SIBLOCK tree under a node's ``bidSub``."""

    def __init__(self, block_reader: BlockReader, variant: Variant, *,
                 sink: WarningSink, max_depth: int = 32):
        self.br = block_reader
        self.variant = variant
        self.sink = sink
        self.max_depth = max_depth

    def iter_subnodes(self, bid_sub: int) -> Iterator[tuple[int, int, int]]:
        """Yield ``(internal_nid, bid_data, bid_sub)`` for every SLENTRY leaf.

        ``bid_sub == 0`` means the node has no subnodes (empty iterator).
        """
        if not bid_sub:
            return
        yield from self._walk(bid_sub, depth=0, seen=set())

    def _walk(self, bid: int, depth: int,
              seen: set[int]) -> Iterator[tuple[int, int, int]]:
        if depth > self.max_depth:
            self.sink.warn(WarnCode.CYCLE_DETECTED, f"depth>{self.max_depth}",
                           where=f"subnode bid={bid:#x}")
            return
        if bid in seen:
            self.sink.warn(WarnCode.CYCLE_DETECTED, "subnode bid revisited",
                           where=f"subnode bid={bid:#x}")
            return
        seen.add(bid)

        raw = self.br.read_raw(bid)
        if raw is None or len(raw) < 4:
            return
        btype = raw[0]
        c_level = raw[1]
        c_ent = int.from_bytes(raw[2:4], "little")
        if btype != SUBNODE_BTYPE:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"subnode btype {btype:#x} != 0x02",
                           where=f"bid={bid:#x}")

        w = self.variant.bid_size
        base = 8 if self.variant.is_unicode else 4  # header + (Unicode) padding

        if c_level == 0:
            # SLBLOCK leaf: SLENTRY = nid(w) bidData(w) bidSub(w)
            stride = 3 * w
            for i in range(c_ent):
                o = base + i * stride
                if o + stride > len(raw):
                    self.sink.warn(WarnCode.ENTRY_OVERFLOW,
                                   f"SLENTRY {i} OOB", where=f"bid={bid:#x}")
                    break
                nid = int.from_bytes(raw[o:o + w], "little") & 0xFFFFFFFF
                bid_data = normalize_bid(int.from_bytes(raw[o + w:o + 2 * w], "little"))
                bid_subc = normalize_bid(int.from_bytes(raw[o + 2 * w:o + 3 * w], "little"))
                yield (nid, bid_data, bid_subc)
        else:
            # SIBLOCK intermediate: SIENTRY = nid(w) bid(w)
            stride = 2 * w
            for i in range(c_ent):
                o = base + i * stride
                if o + stride > len(raw):
                    self.sink.warn(WarnCode.ENTRY_OVERFLOW,
                                   f"SIENTRY {i} OOB", where=f"bid={bid:#x}")
                    break
                child = normalize_bid(int.from_bytes(raw[o + w:o + 2 * w], "little"))
                yield from self._walk(child, depth + 1, seen)
