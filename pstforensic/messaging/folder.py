"""Folder reader — folder PC + hierarchy/contents/FAI TCs (PLAN §6.2).

A folder shares one ``nidIndex`` across four nodes ([MS-PST] §2.4.4):

  * Folder PC      — ``nidType 0x02`` normal / ``0x03`` search.
  * Hierarchy TC   — ``nidType 0x0D``: one row per subfolder; ``dwRowID`` is the
    subfolder's PC NID.
  * Contents TC    — ``nidType 0x0E``: one row per message; ``dwRowID`` is the
    message NID.
  * FAI TC         — ``nidType 0x0F``: associated/system items (surfaced only
    when ``include_fai=True``).

``subfolders()``/``messages()`` are lazy with a **visited-NID cycle guard**
(``CYCLE_DETECTED`` orphans the subtree).  ``path`` is built from display names.
"""
from __future__ import annotations

import struct
from typing import Iterator, Optional

from ..exceptions import WarnCode, WarningSink
from ..ltp.pc import PropertyContext
from ..ltp.tc import TableContext, PID_LTP_ROW_ID
from ..mapi import MapiMessage, MapiObject
from ..ndb.bref import (
    make_nid,
    nid_index,
    NID_TYPE_HIERARCHY_TABLE,
    NID_TYPE_CONTENTS_TABLE,
    NID_TYPE_ASSOC_CONTENTS_TABLE,
)
from ..proptypes import PropType
from .message import build_message

# PidTag ids ([MS-OXCFOLD] §2.2).
PID_DISPLAY_NAME = 0x3001
PID_CONTENT_COUNT = 0x3602
PID_CONTAINER_CLASS = 0x3613


class Folder:
    """A mailbox folder: name, path, lazy subfolders and messages (PLAN §6.2)."""

    def __init__(self, store, pc: MapiObject, pc_nid: int, *,
                 parent_path: str = "", sink: WarningSink,
                 visited: Optional[set[int]] = None,
                 include_fai: bool = False):
        self._store = store
        self.pc = pc
        self.nid = pc_nid
        self.sink = sink
        self._visited = visited if visited is not None else set()
        self._include_fai = include_fai
        self.name = _string_prop(pc, PID_DISPLAY_NAME) or f"0x{pc_nid:08X}"
        self.path = f"{parent_path}/{self.name}" if parent_path else f"/{self.name}"

    # -- container classification -----------------------------------------
    @property
    def container_class(self) -> Optional[str]:
        """PidTagContainerClass (e.g. ``IPF.Note``), or ``None``."""
        return _string_prop(self.pc, PID_CONTAINER_CLASS)

    @property
    def is_dumpster(self) -> bool:
        """Heuristic Recoverable-Items / dumpster detection (PLAN §6.2)."""
        cc = (self.container_class or "").lower()
        if cc == "ipf.ipm.wastebasket":
            return True
        return self.name.lower() in ("recoverable items", "deletions",
                                     "versions", "purges", "discoveryholds")

    # -- children ---------------------------------------------------------
    def subfolders(self) -> list["Folder"]:
        """Direct child folders (lazy DFS, cycle-guarded)."""
        out: list[Folder] = []
        idx = nid_index(self.nid)
        hier_nid = make_nid(NID_TYPE_HIERARCHY_TABLE, idx)
        for child_nid in self._table_row_ids(hier_nid):
            if child_nid in self._visited:
                self.sink.warn(WarnCode.CYCLE_DETECTED,
                               f"folder {child_nid:#x} revisited",
                               where=f"folder nid={self.nid:#x}")
                continue
            child_ref = self._store.nodedb.node(child_nid)
            if child_ref is None:
                # Try the normal-folder PC NID type if the row id wasn't typed.
                self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                               f"subfolder PC node {child_nid:#x} absent",
                               where=f"folder nid={self.nid:#x}")
                continue
            self._visited.add(child_nid)
            child_pc = PropertyContext.from_node(
                child_ref, self._store.variant, sink=self.sink)
            out.append(Folder(self._store, child_pc, child_nid,
                              parent_path=self.path, sink=self.sink,
                              visited=self._visited,
                              include_fai=self._include_fai))
        return out

    def messages(self) -> list[MapiMessage]:
        """Direct child messages (contents TC; FAI added when ``include_fai``)."""
        out: list[MapiMessage] = []
        idx = nid_index(self.nid)
        table_types = [NID_TYPE_CONTENTS_TABLE]
        if self._include_fai:
            table_types.append(NID_TYPE_ASSOC_CONTENTS_TABLE)
        for ttype in table_types:
            table_nid = make_nid(ttype, idx)
            for msg_nid in self._table_row_ids(table_nid):
                msg_ref = self._store.nodedb.node(msg_nid)
                if msg_ref is None:
                    self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                                   f"message node {msg_nid:#x} absent",
                                   where=f"folder nid={self.nid:#x}")
                    continue
                out.append(build_message(
                    msg_ref, self._store.variant, sink=self.sink,
                    renderer_installer=self._store.renderer_installer))
        return out

    def walk(self) -> Iterator["Folder"]:
        """Yield this folder then every descendant (DFS)."""
        yield self
        for sub in self.subfolders():
            yield from sub.walk()

    # -- helpers ----------------------------------------------------------
    def _table_row_ids(self, table_nid: int) -> list[int]:
        """Read a hierarchy/contents TC and return each row's ``dwRowID`` (child NID)."""
        ref = self._store.nodedb.node(table_nid)
        if ref is None:
            return []
        ids: list[int] = []
        for row in TableContext.from_node(ref, self._store.variant,
                                          sink=self.sink):
            v = row.get_tag(PID_LTP_ROW_ID) or row.by_id(0x6748)
            if v is None or len(v.raw) < 4:
                continue
            ids.append(struct.unpack_from("<I", v.raw, 0)[0])
        return ids

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"Folder(name={self.name!r}, nid={self.nid:#x})"


def _string_prop(obj: MapiObject, prop_id: int) -> Optional[str]:
    """Decode a PT_STRING/PT_STRING8 property to text, or ``None`` if absent."""
    v = obj.by_id(prop_id)
    if v is None or not v.raw:
        return None
    ptype = v.prop_type
    if ptype == int(PropType.STRING8):
        return v.raw.decode("cp1252", "replace")
    # PT_STRING (UTF-16LE) or any name field: best-effort UTF-16.
    return v.raw.decode("utf-16-le", "replace")
