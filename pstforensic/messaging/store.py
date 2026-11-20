"""Store bootstrap — ``open_store(source) -> Store`` (PLAN §6.1).

Opens a PST/OST, resolves the message-store Property Context (NID 0x21), locates
the root IPM folder, loads the named-property map (NID 0x61), and exposes the
folder tree.

Bootstrap steps ([MS-PST] §2.4.3 / PLAN §6.1):

  1. Build a :class:`~pstforensic.ndb.nodedb.NodeDatabase` over the source.
  2. Resolve ``NID_MESSAGE_STORE`` (0x21) PC → ``PidTagDisplayName`` (0x3001),
     ``PidTagRecordKey`` (0x0FF9), ``PidTagIpmSubTreeEntryId`` (0x35E0) → root
     folder EntryID → NID.  ``PidTagPstPassword`` (0x67FF) is a CRC-32 hash that
     we **bypass** (read access needs no password) but flag if present.
  3. Load :class:`~pstforensic.messaging.nameid.NamedPropMap` from
     ``NID_NAME_TO_ID_MAP`` (0x61).
"""
from __future__ import annotations

import struct
from typing import Iterator, List, Optional

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from .. import integrity as I
from ..integrity import Integrity
from ..ltp.pc import PropertyContext
from ..mapi import MapiObject
from ..ndb.bref import (
    NID_MESSAGE_STORE,
    NID_NAME_TO_ID_MAP,
    NID_ROOT_FOLDER,
)
from ..ndb.nodedb import NodeDatabase
from .. import render
from .folder import Folder
from .nameid import NamedPropMap

# Message-store PidTag ids ([MS-OXCSTOR] §2.2.2).
PID_DISPLAY_NAME = 0x3001
PID_RECORD_KEY = 0x0FF9
PID_IPM_SUBTREE_ENTRYID = 0x35E0
PID_PST_PASSWORD = 0x67FF


class Store:
    """A parsed PST/OST mail store (PLAN §6.1).

    Attributes:
        nodedb: The underlying :class:`NodeDatabase`.
        variant: The store variant (ANSI / Unicode / 4K).
        named_props: The resolved :class:`NamedPropMap`.
        store_pc: The message-store Property Context (or ``None`` if absent).
        display_name: ``PidTagDisplayName`` of the store, if present.
        record_key: ``PidTagRecordKey`` raw bytes, if present.
        has_password: True iff ``PidTagPstPassword`` was set (bypassed; flagged).
        root_folder: The root IPM folder, or ``None`` if it could not be located.
        warnings: The accumulated :class:`WarningSink`.
    """

    def __init__(self, nodedb: NodeDatabase, *, sink: WarningSink) -> None:
        self.nodedb = nodedb
        self.variant = nodedb.variant
        self.sink = sink
        self.renderer_installer = render.install_renderer

        self.store_pc: Optional[MapiObject] = None
        self.display_name: Optional[str] = None
        self.record_key: Optional[bytes] = None
        self.has_password: bool = False
        self._root_folder_nid: Optional[int] = None

        if nodedb.nbt_damaged:
            # The B-tree cannot reach every node: harvest the file first so
            # the bootstrap and folder walk resolve nodes from the scan.
            nodedb.scan()
        self._bootstrap()
        self.named_props = self._load_named_props()
        self.root_folder = self._open_root_folder()
        self._scan = nodedb._scan
        self.inventory_stats = None

    # -- bootstrap --------------------------------------------------------
    def _bootstrap(self) -> None:
        """Resolve the message-store PC (NID 0x21) and its key envelope props."""
        store_ref = self.nodedb.node(NID_MESSAGE_STORE)
        if store_ref is None:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           "NID_MESSAGE_STORE (0x21) absent",
                           where="store bootstrap")
            return
        pc = PropertyContext.from_node(store_ref, self.variant, sink=self.sink)
        self.renderer_installer(pc)
        self.store_pc = pc

        dn = pc.by_id(PID_DISPLAY_NAME)
        if dn is not None and dn.raw:
            self.display_name = dn.raw.decode("utf-16-le", "replace")
        rk = pc.by_id(PID_RECORD_KEY)
        if rk is not None:
            self.record_key = rk.raw

        # PstPassword: bypass (read access needs no password) but flag (PLAN §6.1).
        pw = pc.by_id(PID_PST_PASSWORD)
        if pw is not None and pw.raw and any(pw.raw[:4]):
            self.has_password = True
            self.sink.warn(WarnCode.SIG_MISMATCH,
                           "PidTagPstPassword set; bypassed (read needs no password)",
                           where="store bootstrap")

        # Root IPM subtree EntryID → root folder NID.
        eid = pc.by_id(PID_IPM_SUBTREE_ENTRYID)
        self._root_folder_nid = self._entryid_nid(eid.raw if eid else None)

    @staticmethod
    def _entryid_nid(raw: Optional[bytes]) -> int:
        """Extract the folder NID from an IPM-subtree EntryID.

        A folder EntryID is ``flags(4) + providerUID(16) + NID(4)`` ([MS-OXCDATA]
        §2.2.4.1); the trailing 4 bytes are the NID.  Falls back to the canonical
        ``NID_ROOT_FOLDER`` (0x122) when the EntryID is missing/short.
        """
        if raw is not None and len(raw) >= 24:
            return struct.unpack_from("<I", raw, 20)[0]
        return NID_ROOT_FOLDER

    def _load_named_props(self) -> NamedPropMap:
        """Load the name-to-id map PC (NID 0x61) → :class:`NamedPropMap` (§6.6)."""
        ref = self.nodedb.node(NID_NAME_TO_ID_MAP)
        pc = None
        if ref is not None:
            pc = PropertyContext.from_node(ref, self.variant, sink=self.sink)
        return NamedPropMap.from_pc(pc, sink=self.sink)

    def _open_root_folder(self) -> Optional[Folder]:
        """Open the root IPM folder Property Context as a :class:`Folder`."""
        nid = self._root_folder_nid if self._root_folder_nid is not None \
            else NID_ROOT_FOLDER
        ref = self.nodedb.node(nid)
        if ref is None:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"root folder node {nid:#x} absent",
                           where="store bootstrap")
            return None
        pc = PropertyContext.from_node(ref, self.variant, sink=self.sink)
        self.renderer_installer(pc)
        return Folder(self, pc, nid, sink=self.sink, visited={nid}, noderef=ref)

    # -- public surface ---------------------------------------------------
    def folders(self) -> Iterator[Folder]:
        """Iterate every folder in the store, root first (recursive DFS)."""
        if self.root_folder is None:
            return iter(())
        return self.root_folder.walk()

    @property
    def warnings(self) -> List:
        """The accumulated parse warnings."""
        return self.sink.warnings

    # -- resilience surface (PLAN §14) -------------------------------------
    def scan(self, *, progress=None, should_abort=None, use_numpy=None):
        """Run (once) the full-file scan and wire it into block resolution.

        After this, BIDs missing from the BBT (freed blocks of deleted items,
        a damaged BBT subtree) resolve from on-disk block trailers and are
        flagged ``BLOCK_FROM_SCAN``.
        """
        self._scan = self.nodedb.scan(progress=progress, should_abort=should_abort,
                                      use_numpy=use_numpy)
        return self._scan

    def iter_items(self, *, include_fai: bool = False, progress=None,
                   should_abort=None):
        """Stream every message the file holds — live, soft/hard-deleted,
        orphaned, superseded, carved, lost — each with state, provenance,
        findings and deletion info (PLAN §14.6).  Memory stays flat; use this
        for large stores.  Policy (what to show) is the caller's."""
        from .inventory import Inventory
        scan = self.scan(progress=progress, should_abort=should_abort)
        inv = Inventory(self, scan, include_fai=include_fai)
        self.inventory_stats = inv.stats
        yield from inv.items()

    def items(self, **kwargs) -> List:
        """:meth:`iter_items` as a list (convenient for small stores)."""
        return list(self.iter_items(**kwargs))

    def recover(self, item):
        """Deep salvage of one item (PLAN §14.8); same as ``item.recover()``."""
        from .salvage import salvage
        return salvage(self, item)

    @property
    def integrity(self) -> Integrity:
        """Store-level findings: header, skipped B-tree pages, scan anomalies."""
        integ = Integrity()
        hdr = self.nodedb.header.integrity
        if hdr is not None:
            integ.extend(hdr.findings)
        for ib in getattr(self.nodedb, "skipped_pages", ()):
            integ.add(I.PAGE_UNREADABLE, "B-tree page skipped (not a page)", ib=ib)
        for ib, v in getattr(self.nodedb, "page_verdicts", {}).items():
            integ.extend(v.findings())
        if self._scan is not None:
            st = self._scan.stats
            if st.foreign_variant_pages:
                integ.add("FOREIGN_VARIANT_PAGES",
                          f"{st.foreign_variant_pages} pages validate only under "
                          "another variant's geometry")
            if not self._scan.complete:
                integ.add("SCAN_INCOMPLETE", "full-file scan aborted")
        if self.inventory_stats is not None and self.inventory_stats.unresolved_deleted:
            integ.add("DELETED_CONTENT_LOST",
                      f"{self.inventory_stats.unresolved_deleted} deleted entries "
                      "whose data is gone or unparseable")
        return integ

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (f"Store(name={self.display_name!r}, variant={self.variant.name}, "
                f"password={self.has_password})")


def open_store(source, *, sink: Optional[WarningSink] = None) -> Store:
    """Open a PST/OST mail store and return its :class:`Store` (PLAN §6.1).

    Args:
        source: A path, ``bytes`` image, or seekable binary stream of a PST/OST.
        sink: Optional :class:`WarningSink`; one is created if omitted.

    Returns:
        A :class:`Store` exposing ``root_folder``, ``folders()``, ``named_props``,
        ``nodedb`` and ``warnings``.

    Raises:
        NotAPstError: If the bytes are not a recognisable PST/OST store.
    """
    sink = sink if sink is not None else WarningSink()
    reader = FileReader(source, sink=sink)
    nodedb = NodeDatabase.open(reader, sink=sink)
    return Store(nodedb, sink=sink)
