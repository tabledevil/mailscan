"""Table Context (TC) — a row/column MAPI table on a heap ([MS-PST] §2.3.4).

A TC is a heap whose ``bClientSig == 0x7C`` and whose ``hidUserRoot`` resolves a
:class:`TCINFO`:

  bType(1)=0x7C, cCols(1), rgib[4] (u16 group-end offsets: TCI_4b, TCI_2b,
  TCI_1b, TCI_bm), hidRowIndex(4) → RowIndex BTH, hnidRows(4) → Row Matrix
  (an HID *or* a subnode NID — Appendix A H23), hidIndex(4, deprecated),
  rgTCOLDESC[cCols].

Each :class:`TCOLDESC` is 8B: tag(4), ibData(2 row offset), cbData(1 width),
iBit(1 CEB index).

Row layout ([MS-PST] §2.3.4.4): every row is ``rgib[TCI_bm]`` bytes — an 8/4B
group, then 2B group, then 1B group, then the **Cell Existence Bitmap (CEB)**.
A column's cell is present iff bit ``iBit`` of the CEB is set; absent ⇒ NULL.

``dwRowID → dwRowIndex`` is resolved through the RowIndex BTH (NOT row order —
Appendix A H23); the Row Matrix is then indexed by ``dwRowIndex``.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterator, Optional

from ..exceptions import WarnCode, WarningSink
from ..mapi import MapiObject, MapiValue
from ..ndb.nodedb import NodeRef
from ..proptypes import (
    base_type,
    fixed_size,
    is_inline_in_pc,
    is_multivalue,
    make_tag,
    split_tag,
)
from ..variant import Variant, UNICODE
from .bth import BTreeOnHeap
from .heap import HN_CLIENT_TC, HeapOnNode, resolve_hid

# TCINFO signature ([MS-PST] §2.3.4.1).
TC_SIG = 0x7C
# rgib indices ([MS-PST] §2.3.4.1).
TCI_4b = 0   # end of the 8/4-byte cell group
TCI_2b = 1   # end of the 2-byte cell group
TCI_1b = 2   # end of the 1-byte cell group
TCI_bm = 3   # end of the row incl. the CEB → row size

# PidTagLtpRowId (0x67480003): the dwRowID column at row offset 0.
PID_LTP_ROW_ID = 0x67480003


@dataclass
class TCOLDESC:
    """One column descriptor ([MS-PST] §2.3.4.2), 8 bytes."""

    tag: int        # (prop_id<<16)|prop_type
    ib_data: int    # byte offset of the cell within a row
    cb_data: int    # cell width
    i_bit: int      # bit index in the Cell Existence Bitmap


@dataclass
class TCINFO:
    """Table Context info header ([MS-PST] §2.3.4.1)."""

    b_type: int
    c_cols: int
    rgib: tuple[int, int, int, int]
    hid_row_index: int
    hnid_rows: int
    columns: list[TCOLDESC]

    @property
    def row_size(self) -> int:
        return self.rgib[TCI_bm]


class TableContext:
    """Parses a TC node into a stream of per-row :class:`MapiObject`s."""

    def __init__(self, noderef: NodeRef, variant: Variant = UNICODE, *,
                 sink: WarningSink | None = None):
        self.noderef = noderef
        self.variant = variant
        self.sink = sink if sink is not None else WarningSink()
        self.heap = HeapOnNode(noderef, variant, sink=self.sink)
        self.info: Optional[TCINFO] = None

    @classmethod
    def from_node(cls, noderef: NodeRef, variant: Variant = UNICODE, *,
                  sink: WarningSink | None = None) -> Iterator[MapiObject]:
        """Parse ``noderef`` as a TC and iterate its rows (CONTRACTS §LTP)."""
        return cls(noderef, variant, sink=sink).rows()

    # -- TCINFO -----------------------------------------------------------
    def _parse_info(self) -> TCINFO:
        raw = self.heap.get_allocation(self.heap.user_root)
        if len(raw) < 22:
            self.sink.warn(WarnCode.TRUNCATED, "TCINFO < 22B",
                           where=f"node={self.noderef.nid:#x}")
            return TCINFO(0, 0, (0, 0, 0, 0), 0, 0, [])
        b_type, c_cols = struct.unpack_from("<BB", raw, 0)
        rgib = struct.unpack_from("<HHHH", raw, 2)
        hid_row_index, hnid_rows, _hid_index = struct.unpack_from("<III", raw, 10)
        if b_type != TC_SIG:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"TCINFO bType {b_type:#x} != 0x7C",
                           where=f"node={self.noderef.nid:#x}")
        cols: list[TCOLDESC] = []
        off = 22  # rgTCOLDESC follows the 22-byte fixed header
        for i in range(c_cols):
            if off + 8 > len(raw):
                self.sink.warn(WarnCode.ENTRY_OVERFLOW,
                               f"TCOLDESC {i} OOB",
                               where=f"node={self.noderef.nid:#x}")
                break
            tag, ib_data, cb_data, i_bit = struct.unpack_from("<IHBB", raw, off)
            cols.append(TCOLDESC(tag, ib_data, cb_data, i_bit))
            off += 8
        return TCINFO(b_type, c_cols, rgib, hid_row_index, hnid_rows, cols)

    # -- row iteration ----------------------------------------------------
    def rows(self) -> Iterator[MapiObject]:
        """Yield one :class:`MapiObject` per live row ([MS-PST] §2.3.4.4)."""
        if self.heap.client_sig != HN_CLIENT_TC:
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           f"TC bClientSig {self.heap.client_sig:#x} != 0x7C",
                           where=f"node={self.noderef.nid:#x}")
        self.info = self._parse_info()
        info = self.info
        if not info.row_size:
            return
        matrix = self._read_row_matrix(info.hnid_rows)
        if not matrix:
            return
        row_index = self._read_row_index(info.hid_row_index)
        ceb_bytes = info.rgib[TCI_bm] - info.rgib[TCI_1b]
        row_size = info.row_size
        total_rows = len(matrix) // row_size

        if row_index:
            # Map dwRowID → dwRowIndex (Appendix A H23) and emit in that order.
            order = sorted(row_index.items(), key=lambda kv: kv[1])
            for _row_id, idx in order:
                if 0 <= idx < total_rows:
                    yield self._build_row(matrix, idx, info, ceb_bytes)
                else:
                    self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                                   f"dwRowIndex {idx} >= {total_rows} rows",
                                   where=f"node={self.noderef.nid:#x}")
        else:
            # No/empty RowIndex: linear scan with CEB validation (recovery path).
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           "TC RowIndex absent; linear scan",
                           where=f"node={self.noderef.nid:#x}")
            for idx in range(total_rows):
                yield self._build_row(matrix, idx, info, ceb_bytes)

    def _build_row(self, matrix: bytes, idx: int, info: TCINFO,
                   ceb_bytes: int) -> MapiObject:
        """Decode one row into a :class:`MapiObject`, honouring the CEB."""
        row_size = info.row_size
        base = idx * row_size
        row = matrix[base:base + row_size]
        obj = MapiObject(nid=self.noderef.nid)
        ceb_off = info.rgib[TCI_1b]
        ceb = row[ceb_off:ceb_off + ceb_bytes]
        for col in info.columns:
            if not self._cell_present(ceb, col.i_bit):
                continue  # NULL cell — omit (CEB)
            cell = row[col.ib_data:col.ib_data + col.cb_data]
            mv = self._read_cell(col, cell)
            if mv is not None:
                obj.add(mv)
        return obj

    @staticmethod
    def _cell_present(ceb: bytes, i_bit: int) -> bool:
        """True iff CEB bit ``i_bit`` is set (cell present, [MS-PST] §2.3.4.4.1).

        The CEB is big-endian-bit: the first byte holds bits 0-7 with bit 0 the
        most significant (``0x80``).
        """
        byte_i = i_bit // 8
        if byte_i >= len(ceb):
            return False
        return bool(ceb[byte_i] & (0x80 >> (i_bit % 8)))

    def _read_cell(self, col: TCOLDESC, cell: bytes) -> Optional[MapiValue]:
        """Decode one cell, resolving variable/large columns like PC values."""
        _pid, ptype = split_tag(col.tag)
        if is_inline_in_pc(ptype):
            width = fixed_size(ptype) or col.cb_data
            return MapiValue(tag=col.tag, raw=cell[:width])
        # Variable / large fixed (8/16B) / MV / object: the cell holds an HNID.
        if len(cell) < 4:
            return MapiValue(tag=col.tag, raw=cell)
        hnid = struct.unpack_from("<I", cell, 0)[0]
        raw = self._resolve_hnid(hnid)
        if raw is None:
            return MapiValue(tag=col.tag, raw=b"")
        if is_multivalue(ptype):
            return MapiValue(tag=col.tag, raw=raw,
                             elements=self._split_mv(ptype, raw))
        return MapiValue(tag=col.tag, raw=raw)

    def _resolve_hnid(self, hnid: int) -> Optional[bytes]:
        """Resolve an HNID (heap HID or subnode NID), classified by low bits."""
        if hnid == 0:
            return b""
        h = resolve_hid(hnid)
        if h.is_hid:
            return self.heap.get_allocation(hnid)
        ref = self.noderef.subnodes().get(hnid)
        if ref is None:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"TC cell subnode nid {hnid:#x} absent",
                           where=f"node={self.noderef.nid:#x}")
            return None
        return ref.data_stream()

    def _split_mv(self, ptype: int, raw: bytes) -> list[bytes]:
        """Split a TC MV cell exactly like PC ([MS-PST] §2.3.3.4)."""
        if len(raw) < 4:
            return []
        count = struct.unpack_from("<I", raw, 0)[0]
        width = fixed_size(base_type(ptype))
        out: list[bytes] = []
        if width is not None:
            off = 4
            for _ in range(count):
                if off + width > len(raw):
                    break
                out.append(raw[off:off + width])
                off += width
            return out
        need = 4 + (count + 1) * 4
        if need > len(raw):
            return []
        offsets = [struct.unpack_from("<I", raw, 4 + i * 4)[0]
                   for i in range(count + 1)]
        for i in range(count):
            s, e = offsets[i], offsets[i + 1]
            if not (0 <= s <= e <= len(raw)):
                break
            out.append(raw[s:e])
        return out

    # -- row matrix / row index -------------------------------------------
    def _read_row_matrix(self, hnid_rows: int) -> bytes:
        """Read the Row Matrix bytes — an HID or a subnode NID (Appendix A H23)."""
        if hnid_rows == 0:
            return b""
        h = resolve_hid(hnid_rows)
        if h.is_hid:
            return self.heap.get_allocation(hnid_rows)
        ref = self.noderef.subnodes().get(hnid_rows)
        if ref is None:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"Row Matrix subnode nid {hnid_rows:#x} absent",
                           where=f"node={self.noderef.nid:#x}")
            return b""
        return ref.data_stream()

    def _read_row_index(self, hid_row_index: int) -> dict[int, int]:
        """Parse the RowIndex BTH → ``{dwRowID: dwRowIndex}`` ([MS-PST] §2.3.4.3).

        The RowIndex is a BTH with cbKey=4 (dwRowID) and cbEnt=4 (dwRowIndex).
        Absent/``hidRowIndex==0`` ⇒ empty map (caller falls back to linear scan).
        """
        if hid_row_index == 0:
            return {}
        bth = BTreeOnHeap(self.heap, hid_row_index, sink=self.sink)
        out: dict[int, int] = {}
        for key, val in bth.records():
            if len(key) < 4 or len(val) < 4:
                continue
            row_id = struct.unpack_from("<I", key, 0)[0]
            row_idx = struct.unpack_from("<I", val, 0)[0]
            out[row_id] = row_idx
        return out
