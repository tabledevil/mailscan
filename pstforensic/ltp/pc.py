"""Property Context (PC) — a node's MAPI property bag ([MS-PST] §2.3.3).

A PC is a heap whose ``bClientSig == 0xBC`` and whose ``hidUserRoot`` roots a
BTH with ``cbKey=2`` (wPropId) and ``cbEnt=6`` (wPropType:2 + dwValueHnid:4).
Each leaf record describes one property.

Storage decision (Appendix A H5/H6, [MS-PST] §2.3.3.3):
  * ``is_inline_in_pc(ptype)`` (≤4B fixed) ⇒ the 4 ``dwValueHnid`` bytes ARE the
    value (so only 4 bytes are ever inline — H5).
  * otherwise ``dwValueHnid`` is an **HNID**: classify by its low bits *first*
    (``hidType == 0`` ⇒ heap HID, else a subnode local-NID — H6), resolve, THEN
    size-validate against the type's expected width.
  * variable / MV types ≤3580B reference a heap HID; >3580B a subnode NID.

MV types ([MS-PST] §2.3.3.4): a fixed-width MV is ``ulCount`` + N fixed items;
a variable-width MV is ``ulCount`` + an offset table (``ulCount+1`` u32) + N
length-prefixed blocks.  Both split into :attr:`MapiValue.elements`.
"""
from __future__ import annotations

import struct
from typing import Optional

from ..exceptions import WarnCode, WarningSink
from ..mapi import MapiObject, MapiValue
from ..ndb.bref import nid_type
from ..ndb.nodedb import NodeRef
from ..proptypes import (
    base_type,
    fixed_size,
    is_inline_in_pc,
    is_multivalue,
    make_tag,
)
from ..variant import Variant, UNICODE
from .bth import BTreeOnHeap
from .heap import HN_CLIENT_PC, HeapOnNode, resolve_hid

# Max heap allocation size; larger values live in a subnode ([MS-PST] §2.3.3.3).
MAX_HEAP_ALLOC = 3580


class PropertyContext:
    """Parses a PC node into a :class:`MapiObject` ([MS-PST] §2.3.3)."""

    def __init__(self, noderef: NodeRef, variant: Variant = UNICODE, *,
                 sink: WarningSink | None = None):
        self.noderef = noderef
        self.variant = variant
        self.sink = sink if sink is not None else WarningSink()
        self.heap = HeapOnNode(noderef, variant, sink=self.sink)

    @classmethod
    def from_node(cls, noderef: NodeRef, variant: Variant = UNICODE, *,
                  sink: WarningSink | None = None) -> MapiObject:
        """Parse ``noderef`` as a PC and return its :class:`MapiObject`.

        The contract surface other tiers import (CONTRACTS §LTP).
        """
        return cls(noderef, variant, sink=sink).parse()

    def parse(self) -> MapiObject:
        """Walk the PC BTH, producing one :class:`MapiValue` per property."""
        obj = MapiObject(nid=self.noderef.nid)
        if self.heap.client_sig != HN_CLIENT_PC:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"PC bClientSig {self.heap.client_sig:#x} != 0xBC",
                           where=f"node={self.noderef.nid:#x}")
        bth = BTreeOnHeap.from_heap(self.heap, sink=self.sink)
        if bth.header.cb_key != 2 or bth.header.cb_ent != 6:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"PC BTH cbKey/cbEnt = {bth.header.cb_key}/"
                           f"{bth.header.cb_ent}, expected 2/6",
                           where=f"node={self.noderef.nid:#x}")
        for key, val in bth.records():
            if len(key) < 2 or len(val) < 6:
                continue
            prop_id = struct.unpack_from("<H", key, 0)[0]
            prop_type, dw_value_hnid = struct.unpack_from("<HI", val, 0)
            tag = make_tag(prop_id, prop_type)
            mv = self._read_property(tag, prop_type, dw_value_hnid,
                                     val[2:6])
            if mv is not None:
                obj.add(mv)
        obj.flags |= self.sink.codes()
        return obj

    # -- value resolution -------------------------------------------------
    def _read_property(self, tag: int, prop_type: int, hnid: int,
                       inline_bytes: bytes) -> Optional[MapiValue]:
        """Resolve one property's raw bytes per the H5/H6 storage rules."""
        if is_inline_in_pc(prop_type):
            # ≤4B fixed type: the dwValueHnid field IS the value (H5).
            width = fixed_size(prop_type) or 4
            return MapiValue(tag=tag, raw=inline_bytes[:width])

        raw = self._resolve_hnid(hnid, tag)
        if raw is None:
            return MapiValue(tag=tag, raw=b"")

        if is_multivalue(prop_type):
            elements = self._split_mv(prop_type, raw, tag)
            return MapiValue(tag=tag, raw=raw, elements=elements)

        # Size-validate fixed >4B types against expected width (H6).
        exp = fixed_size(prop_type)
        if exp is not None and len(raw) < exp:
            self.sink.warn(WarnCode.TRUNCATED,
                           f"fixed prop {tag:#010x} {len(raw)}B < {exp}B",
                           where=f"node={self.noderef.nid:#x}")
        return MapiValue(tag=tag, raw=raw)

    def _resolve_hnid(self, hnid: int, tag: int) -> Optional[bytes]:
        """Resolve an HNID to its bytes, classifying by low bits first (H6).

        ``hidType == 0`` ⇒ a heap HID; otherwise it is a subnode local-NID whose
        data stream holds the value (variable/large properties — §2.3.3.3).
        """
        if hnid == 0:
            return b""
        h = resolve_hid(hnid)
        if h.is_hid:
            return self.heap.get_allocation(hnid)
        # Subnode NID: resolve via the node's subnode tree.
        subs = self.noderef.subnodes()
        ref = subs.get(hnid)
        if ref is None:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"prop {tag:#010x} subnode nid {hnid:#x} absent",
                           where=f"node={self.noderef.nid:#x}")
            return None
        return ref.data_stream()

    # -- multi-value ------------------------------------------------------
    def _split_mv(self, prop_type: int, raw: bytes,
                  tag: int) -> list[bytes]:
        """Split an MV blob into element byte-strings ([MS-PST] §2.3.3.4)."""
        if len(raw) < 4:
            return []
        count = struct.unpack_from("<I", raw, 0)[0]
        elem_type = base_type(prop_type)
        width = fixed_size(elem_type)
        if width is not None:
            # Fixed-width MV: ulCount + N items of ``width`` bytes.
            elements: list[bytes] = []
            off = 4
            for _ in range(count):
                if off + width > len(raw):
                    self.sink.warn(WarnCode.TRUNCATED,
                                   f"MV {tag:#010x} short fixed array",
                                   where=f"node={self.noderef.nid:#x}")
                    break
                elements.append(raw[off:off + width])
                off += width
            return elements
        # Variable-width MV: ulCount + (count+1) u32 offsets + blocks.
        elements = []
        need = 4 + (count + 1) * 4
        if need > len(raw):
            self.sink.warn(WarnCode.TRUNCATED,
                           f"MV {tag:#010x} short offset table",
                           where=f"node={self.noderef.nid:#x}")
            return []
        offsets = [struct.unpack_from("<I", raw, 4 + i * 4)[0]
                   for i in range(count + 1)]
        prev = offsets[0]
        for i in range(count):
            start, end = offsets[i], offsets[i + 1]
            if not (prev <= start <= end <= len(raw)):
                self.sink.warn(WarnCode.SIG_MISMATCH,
                               f"MV {tag:#010x} non-monotonic offsets",
                               where=f"node={self.noderef.nid:#x}")
                break
            elements.append(raw[start:end])
            prev = end
        return elements
