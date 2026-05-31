"""BTree-on-Heap (BTH) — sorted key/value records in a heap ([MS-PST] §2.3.2).

A BTH is rooted by a :class:`HNHDR.hidUserRoot` (when ``bClientSig == 0xB5``) or
by any HID pointing at a :class:`BTHHEADER`.  The header declares the key width
(``cbKey``), the entry/value width (``cbEnt``), and ``bIdxLevels`` (0 ⇒ the root
HID is the leaf record array; >0 ⇒ it is an intermediate level of
``(key, hidNextLevel)`` pairs).

Recovery-first ([MS-PST] §0.5): if the key ordering is broken or the tree is
truncated we warn and fall back to a flat linear scan so a corrupt BTH still
yields its records (keep-first on duplicate keys).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator

from ..exceptions import WarnCode, WarningSink
from .heap import HeapOnNode, resolve_hid

# BTHHEADER signature ([MS-PST] §2.3.2.1).
BTH_SIG = 0xB5
_VALID_CBKEY = frozenset({2, 4, 8, 16})


@dataclass
class BTHHEADER:
    """BTree-on-Heap header ([MS-PST] §2.3.2.1), 8 bytes."""

    b_type: int        # 0xB5
    cb_key: int        # key width, one of {2,4,8,16}
    cb_ent: int        # data/value width
    b_idx_levels: int  # 0 ⇒ leaf is the root; >0 ⇒ intermediate levels
    hid_root: int      # HID of the root record array


class BTreeOnHeap:
    """Walks a BTH and yields its ``(key_bytes, value_bytes)`` leaf records.

    The walk is key-order tolerant: an out-of-order or duplicate key triggers a
    ``SIG_MISMATCH`` warning and a flat linear re-scan (Appendix A / §2.3.2),
    never an abort.
    """

    def __init__(self, heap: HeapOnNode, hid_root: int, *,
                 sink: WarningSink | None = None):
        self.heap = heap
        self.sink = sink if sink is not None else heap.sink
        self.header = self._parse_header(hid_root)

    @classmethod
    def from_heap(cls, heap: HeapOnNode, *,
                  sink: WarningSink | None = None) -> "BTreeOnHeap":
        """Build a BTH rooted at the heap's ``hidUserRoot`` ([MS-PST] §2.3.2)."""
        return cls(heap, heap.user_root, sink=sink)

    # -- header -----------------------------------------------------------
    def _parse_header(self, hid_root: int) -> BTHHEADER:
        raw = self.heap.get_allocation(hid_root)
        if len(raw) < 8:
            self.sink.warn(WarnCode.TRUNCATED, "BTHHEADER < 8B",
                           where=f"hid={hid_root:#x}")
            return BTHHEADER(0, 0, 0, 0, 0)
        b_type, cb_key, cb_ent, b_idx = struct.unpack_from("<BBBB", raw, 0)
        hid = struct.unpack_from("<I", raw, 4)[0]
        if b_type != BTH_SIG:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"BTH bType {b_type:#x} != 0xB5",
                           where=f"hid={hid_root:#x}")
        if cb_key not in _VALID_CBKEY:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"BTH cbKey {cb_key} not in {{2,4,8,16}}",
                           where=f"hid={hid_root:#x}")
        return BTHHEADER(b_type, cb_key, cb_ent, b_idx, hid)

    # -- traversal --------------------------------------------------------
    def records(self) -> Iterator[tuple[bytes, bytes]]:
        """Yield every leaf ``(key, value)`` in key order ([MS-PST] §2.3.2.3)."""
        h = self.header
        if not h.hid_root or h.cb_key == 0:
            return
        yield from self._walk(h.hid_root, h.b_idx_levels, depth=0, seen=set())

    def _walk(self, hid: int, levels: int, depth: int,
              seen: set[int]) -> Iterator[tuple[bytes, bytes]]:
        if depth > 32 or hid in seen:
            self.sink.warn(WarnCode.CYCLE_DETECTED, "BTH walk cycle/too deep",
                           where=f"hid={hid:#x}")
            return
        seen.add(hid)
        raw = self.heap.get_allocation(hid)
        if not raw:
            return
        if levels == 0:
            yield from self._leaf_records(raw)
            return
        # Intermediate: array of (key[cbKey], hidNextLevel[4]) ([MS-PST] §2.3.2.2).
        stride = self.header.cb_key + 4
        if stride <= 0:
            return
        count = len(raw) // stride
        for i in range(count):
            o = i * stride
            child = struct.unpack_from("<I", raw, o + self.header.cb_key)[0]
            yield from self._walk(child, levels - 1, depth + 1, seen)

    def _leaf_records(self, raw: bytes) -> Iterator[tuple[bytes, bytes]]:
        """Split a leaf allocation into records, validating key order."""
        ck, ce = self.header.cb_key, self.header.cb_ent
        stride = ck + ce
        if stride <= 0:
            return
        count = len(raw) // stride
        records: list[tuple[bytes, bytes]] = []
        prev: bytes | None = None
        ordered = True
        for i in range(count):
            o = i * stride
            key = raw[o:o + ck]
            val = raw[o + ck:o + ck + ce]
            records.append((key, val))
            if prev is not None and key <= prev:
                ordered = False
            prev = key
        if not ordered:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           "BTH leaf keys out of order; linear scan",
                           where=f"node={self.heap._noderef.nid:#x}")
            # keep-first on duplicate keys (recovery)
            seen_keys: set[bytes] = set()
            for key, val in records:
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                yield key, val
            return
        yield from records

    def find(self, key: bytes) -> bytes | None:
        """Return the value for ``key`` (exact match), or ``None``.

        Used by the TC RowIndex lookup (dwRowID → dwRowIndex, Appendix A H23).
        """
        for k, v in self.records():
            if k == key:
                return v
        return None
