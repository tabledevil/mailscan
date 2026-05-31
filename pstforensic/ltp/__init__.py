"""LTP (Lists, Tables, Properties) layer — heap, BTH, PC, TC ([MS-PST] §2.3).

This layer turns an NDB :class:`~pstforensic.ndb.nodedb.NodeRef` into MAPI
objects:

  * a **Property Context** (PC, ``bClientSig 0xBC``) →
    :meth:`PropertyContext.from_node` → one :class:`~pstforensic.mapi.MapiObject`.
  * a **Table Context** (TC, ``bClientSig 0x7C``) →
    :meth:`TableContext.from_node` → an iterator of one MapiObject per row.

Both ride on the :class:`HeapOnNode` allocator and the :class:`BTreeOnHeap`
ordered key/value index.
"""
from .heap import HeapOnNode, Hid, resolve_hid
from .bth import BTreeOnHeap, BTHHEADER
from .pc import PropertyContext
from .tc import TableContext, TCINFO, TCOLDESC

__all__ = [
    "HeapOnNode",
    "Hid",
    "resolve_hid",
    "BTreeOnHeap",
    "BTHHEADER",
    "PropertyContext",
    "TableContext",
    "TCINFO",
    "TCOLDESC",
]
