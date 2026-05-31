"""Heap-on-Node (HN) — the LTP allocation layer ([MS-PST] §2.3.1).

A *Heap-on-Node* turns a node's reassembled data stream into a flat allocator
addressed by **HID**s.  The first data block opens with an :class:`HNHDR`; every
continuation block opens with one of two smaller headers (:class:`HNPAGEHDR` or
:class:`HNBITMAPHDR` — Appendix A H24: they share the ``ibHnpm`` field position
but are otherwise distinct structures).  Each block ends with an
:class:`HNPAGEMAP` whose ``rgibAlloc`` table gives allocation extents.

HID resolution (Appendix A H2 / [MS-PST] §2.2.2.1):
  * ``hidType``      = bits 0-4   (MUST be 0 for a HID)
  * ``hidIndex``     = bits 5-15  (**1-based**, value 0 is invalid → warn)
  * ``hidBlockIndex``= bits 16-31 (0-based index of the heap block)

The block stream is the NDB-reassembled data of one node; we re-split it on
``block_align`` (64-byte) boundaries the way it sits on disk so per-block
HNPAGEMAPs land where the spec puts them.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from ..exceptions import WarnCode, WarningSink
from ..ndb.block import block_disk_size
from ..ndb.nodedb import NodeRef
from ..variant import Variant, UNICODE

# Heap header signature ([MS-PST] §2.3.1.2).
HN_SIG = 0xEC

# bClientSig values ([MS-PST] §2.3.1.2): which higher LTP structure lives here.
HN_CLIENT_PC = 0xBC    # Property Context
HN_CLIENT_TC = 0x7C    # Table Context
HN_CLIENT_BTH = 0xB5   # BTree-on-Heap

# HID field geometry ([MS-PST] §2.2.2.1).
_HID_TYPE_MASK = 0x1F          # bits 0-4
_HID_INDEX_SHIFT = 5
_HID_INDEX_MASK = 0x7FF        # 11 bits (bits 5-15)
_HID_BLOCK_SHIFT = 16


@dataclass(frozen=True)
class Hid:
    """A decoded Heap ID ([MS-PST] §2.2.2.1)."""

    raw: int
    hid_type: int       # bits 0-4 (0 ⇒ HID)
    hid_index: int      # bits 5-15, 1-based
    block_index: int    # bits 16-31, 0-based

    @property
    def is_hid(self) -> bool:
        """True iff this is a heap HID (``hidType == 0``), not a subnode NID."""
        return self.hid_type == 0

    @property
    def is_null(self) -> bool:
        """True for the canonical null HID (all-zero raw)."""
        return self.raw == 0


def resolve_hid(hid: int) -> Hid:
    """Split a 32-bit HID into its three fields ([MS-PST] §2.2.2.1, Appendix A H2).

    ``hidIndex`` is **1-based**; a HID whose ``hidType == 0`` but ``hidIndex == 0``
    is malformed (callers should treat it as a null/absent allocation and warn).
    """
    hid &= 0xFFFFFFFF
    return Hid(
        raw=hid,
        hid_type=hid & _HID_TYPE_MASK,
        hid_index=(hid >> _HID_INDEX_SHIFT) & _HID_INDEX_MASK,
        block_index=(hid >> _HID_BLOCK_SHIFT) & 0xFFFF,
    )


@dataclass
class HNHDR:
    """First-block heap header ([MS-PST] §2.3.1.2), 12 bytes."""

    ib_hnpm: int
    b_sig: int
    b_client_sig: int
    hid_user_root: int


@dataclass
class HNPAGEHDR:
    """Continuation-block header ([MS-PST] §2.3.1.3), 2 bytes (ibHnpm only)."""

    ib_hnpm: int


@dataclass
class HNBITMAPHDR:
    """Bitmap-page header ([MS-PST] §2.3.1.4), 66 bytes (ibHnpm + 64B fill map)."""

    ib_hnpm: int
    rgb_fill_level: bytes  # 64 bytes


@dataclass
class HNPAGEMAP:
    """Allocation map at the end of a heap block ([MS-PST] §2.3.1.5).

    Allocation ``i`` occupies ``[rgib_alloc[i], rgib_alloc[i+1])`` within the
    block.  ``rgib_alloc`` has ``c_alloc + 1`` entries.
    """

    c_alloc: int
    c_free: int
    rgib_alloc: list[int]


def _is_bitmap_block(block_index: int) -> bool:
    """True iff continuation block ``block_index`` carries an HNBITMAPHDR.

    [MS-PST] §2.3.1.4: bitmap headers appear on blocks 8, 136, 264, ... i.e.
    the first continuation block and every 128th thereafter (``(idx-8) % 128``).
    Block 0 always uses the HNHDR; blocks 1..7 use the 2-byte HNPAGEHDR.
    """
    if block_index == 0:
        return False
    return block_index == 8 or (block_index > 8 and (block_index - 8) % 128 == 0)


class HeapOnNode:
    """Heap allocator over a node's data stream ([MS-PST] §2.3.1).

    Parses the per-block headers and HNPAGEMAPs once, then serves
    ``get_allocation(hid)`` to any consumer (BTH/PC/TC).  ``client_sig`` exposes
    the heap's role (PC ``0xBC`` / TC ``0x7C`` / BTH ``0xB5``).
    """

    def __init__(self, noderef: NodeRef, variant: Variant = UNICODE, *,
                 sink: WarningSink | None = None):
        self._noderef = noderef
        self.variant = variant
        self.sink = sink if sink is not None else WarningSink()
        self._data = noderef.data_stream()
        # Per-block: (block_bytes, HNPAGEMAP). Index == heap block index.
        self._blocks: list[tuple[bytes, Optional[HNPAGEMAP]]] = []
        self.hdr: Optional[HNHDR] = None
        self._parse()

    # -- public surface ---------------------------------------------------
    @property
    def client_sig(self) -> int:
        """The heap's bClientSig (0xBC PC / 0x7C TC / 0xB5 BTH)."""
        return self.hdr.b_client_sig if self.hdr else 0

    @property
    def user_root(self) -> int:
        """hidUserRoot HID from the HNHDR ([MS-PST] §2.3.1.2)."""
        return self.hdr.hid_user_root if self.hdr else 0

    def get_allocation(self, hid: int) -> bytes:
        """Return the raw bytes of heap allocation ``hid`` ([MS-PST] §2.3.1.5).

        Honours the 1-based ``hidIndex`` rule (Appendix A H2): an index of 0,
        an out-of-range block, or an out-of-range index warns and returns
        ``b""`` rather than raising (recovery-first).
        """
        h = resolve_hid(hid)
        if h.is_null:
            return b""
        if not h.is_hid:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"hid {hid:#x} hidType={h.hid_type} is a subnode NID",
                           where=f"node={self._noderef.nid:#x}")
            return b""
        if h.hid_index == 0:
            # 1-based: index 0 is reserved/invalid (Appendix A H2).
            self.sink.warn(WarnCode.ENTRY_OVERFLOW,
                           f"hidIndex 0 is invalid (1-based) for hid {hid:#x}",
                           where=f"node={self._noderef.nid:#x}")
            return b""
        if h.block_index >= len(self._blocks):
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"hidBlockIndex {h.block_index} >= "
                           f"{len(self._blocks)} blocks",
                           where=f"hid={hid:#x}")
            return b""
        block, pmap = self._blocks[h.block_index]
        if pmap is None:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS, "no HNPAGEMAP in block",
                           where=f"hid={hid:#x}")
            return b""
        i = h.hid_index - 1  # 1-based → 0-based array index
        if i + 1 >= len(pmap.rgib_alloc):
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"hidIndex {h.hid_index} out of rgibAlloc "
                           f"(cAlloc={pmap.c_alloc})", where=f"hid={hid:#x}")
            return b""
        start = pmap.rgib_alloc[i]
        end = pmap.rgib_alloc[i + 1]
        if not (0 <= start <= end <= len(block)):
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"allocation [{start},{end}) outside block "
                           f"({len(block)}B)", where=f"hid={hid:#x}")
            return b""
        return block[start:end]

    # -- parsing ----------------------------------------------------------
    def _parse(self) -> None:
        """Split the data stream into heap blocks and parse each HNPAGEMAP."""
        for idx, block in enumerate(self._iter_blocks()):
            if idx == 0:
                if len(block) < 12:
                    self.sink.warn(WarnCode.TRUNCATED, "HNHDR < 12B",
                                   where=f"node={self._noderef.nid:#x}")
                    self._blocks.append((block, None))
                    continue
                ib_hnpm, b_sig, b_client, hid_root = struct.unpack_from(
                    "<HBBI", block, 0)
                self.hdr = HNHDR(ib_hnpm, b_sig, b_client, hid_root)
                if b_sig != HN_SIG:
                    self.sink.warn(WarnCode.SIG_MISMATCH,
                                   f"HN bSig {b_sig:#x} != 0xEC",
                                   where=f"node={self._noderef.nid:#x}")
            else:
                ib_hnpm = self._continuation_ib_hnpm(idx, block)
            pmap = self._parse_pagemap(block, ib_hnpm, idx)
            self._blocks.append((block, pmap))

    def _continuation_ib_hnpm(self, idx: int, block: bytes) -> int:
        """Read ``ibHnpm`` from a continuation block's header (HNPAGEHDR/HNBITMAPHDR).

        Appendix A H24: the two header forms differ in size (2B vs 66B) but the
        ``ibHnpm`` u16 is at offset 0 in both, which is all we need to locate
        the HNPAGEMAP.  We still distinguish them for spec fidelity / parsing.
        """
        if len(block) < 2:
            return 0
        ib_hnpm = struct.unpack_from("<H", block, 0)[0]
        if _is_bitmap_block(idx):
            # HNBITMAPHDR: ibHnpm(2) + rgbFillLevel(64). Parsed for completeness.
            _ = block[2:66]
        return ib_hnpm

    def _parse_pagemap(self, block: bytes, ib_hnpm: int,
                       idx: int) -> Optional[HNPAGEMAP]:
        """Parse the HNPAGEMAP at ``ib_hnpm`` ([MS-PST] §2.3.1.5)."""
        if ib_hnpm + 4 > len(block):
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"ibHnpm {ib_hnpm} past block {len(block)}B",
                           where=f"node={self._noderef.nid:#x} block={idx}")
            return None
        c_alloc, c_free = struct.unpack_from("<HH", block, ib_hnpm)
        rgib: list[int] = []
        off = ib_hnpm + 4
        need = (c_alloc + 1) * 2
        if off + need > len(block):
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"rgibAlloc[{c_alloc + 1}] past block",
                           where=f"node={self._noderef.nid:#x} block={idx}")
            avail = (len(block) - off) // 2
            count = max(avail, 0)
        else:
            count = c_alloc + 1
        for k in range(count):
            rgib.append(struct.unpack_from("<H", block, off + k * 2)[0])
        return HNPAGEMAP(c_alloc=c_alloc, c_free=c_free, rgib_alloc=rgib)

    def _iter_blocks(self):
        """Yield the node stream re-split on its on-disk block boundaries.

        The NDB layer concatenated child data blocks (each ``cb`` payload bytes,
        no trailer) when reassembling an XBLOCK stream.  The HN spec places one
        HNPAGEMAP at the end of every such heap block, so we re-split the stream
        into the same payload-sized chunks.  For a single-block node the whole
        stream is one heap block.
        """
        data = self._data
        if not data:
            return
        # Heap block payload capacity = max on-disk data block payload.  The
        # largest block holds (block bytes - trailer) payload; the synth/NDB
        # uses the standard max data block of 8192 bytes on disk.
        cap = self._max_payload()
        if len(data) <= cap:
            yield data
            return
        off = 0
        n = len(data)
        while off < n:
            yield data[off:off + cap]
            off += cap

    def _max_payload(self) -> int:
        """Max payload bytes per heap (data) block ([MS-PST] §2.2.2.8).

        A data block tops out at 8192 bytes on disk, so its payload capacity is
        ``8192 - block_trailer_size``.  Sub-8K blocks store their HNPAGEMAP at
        the end of their own payload, which ``block_disk_size`` already reflects.
        """
        return 8192 - self.variant.block_trailer_size
