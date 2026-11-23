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

    def __init__(self, nodedb: NodeDatabase, *, sink: WarningSink,
                 progress=None, should_abort=None) -> None:
        self.nodedb = nodedb
        self.variant = nodedb.variant
        self.sink = sink
        self.renderer_installer = render.install_renderer

        self.store_pc: Optional[MapiObject] = None
        self.display_name: Optional[str] = None
        self.record_key: Optional[bytes] = None
        self.has_password: bool = False
        self._root_folder_nid: Optional[int] = None

        from ..diagnostics import Diagnostics
        self.diag = Diagnostics()
        self.progress = progress          # progress(phase, done, total, found)
        self.inventory_stats = None
        self.inventory = None
        self._scan = None
        if nodedb.nbt_damaged or nodedb.bbt_damaged:
            # A B-tree cannot reach every node/block: harvest the file first
            # so the bootstrap and folder walk resolve them from the scan.
            self.scan(should_abort=should_abort)
        with self.diag.timed("open"):
            self._bootstrap()
            self.named_props = self._load_named_props()
            self.root_folder = self._open_root_folder()
        self._scan = nodedb._scan

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
        if progress is None and self.progress is not None:
            size = self.nodedb.reader.size
            cb = self.progress

            def progress(done: int, total: int) -> None:
                # The scan runs two passes over the file: pages, then blocks.
                if done <= size:
                    cb("scan_pages", done, size, None)
                else:
                    cb("scan_blocks", done - size, size, None)
        if self.nodedb._scan is None or not self.nodedb._scan.complete:
            with self.diag.timed("scan"):
                self.nodedb.scan(progress=progress, should_abort=should_abort,
                                 use_numpy=use_numpy)
        self._scan = self.nodedb._scan
        return self._scan

    def iter_items(self, *, include_fai: bool = False, progress=None,
                   should_abort=None, carving: str = "inline", on_carved=None):
        """Stream every message the file holds — live, soft/hard-deleted,
        orphaned, superseded, carved, lost — each with state, provenance,
        findings and deletion info (PLAN §14.6).  Memory stays flat; use this
        for large stores.  Policy (what to show) is the caller's.

        ``carving`` — the items only free-space carving finds (``carved``, and
        ``lost`` PCs no node reaches):

        * ``"inline"`` (default): yielded last, the stream is complete.
        * ``"background"``: the stream ends with the structural items; carving
          runs in a background thread, hands each find to ``on_carved(item)``
          and :meth:`carved_items` blocks until it is complete.
        * ``"skip"``: not run; :meth:`carved_items` runs it on demand.
        """
        from .inventory import Inventory
        scan = self.scan(progress=progress, should_abort=should_abort)
        inv = Inventory(self, scan, include_fai=include_fai,
                        progress=self.progress, should_abort=should_abort,
                        carving=carving, on_carved=on_carved)
        self.inventory_stats = inv.stats
        self.inventory = inv
        yield from inv.items()

    def carved_items(self, *, wait: bool = True, timeout: Optional[float] = None) -> list:
        """The carved/lost-in-free-space items.  Blocks until the carving
        index is complete (``wait``); starts carving if it never ran."""
        inv = self.inventory
        if inv is None:
            for _ in self.iter_items(carving="skip"):
                pass
            inv = self.inventory
        if inv.job is None:
            if inv.carving == "inline":
                if not inv.complete:          # stream not consumed yet
                    for _ in inv.items():
                        pass
                return [self.item(r) for r in inv.records
                        if r["provenance"] in ("free_space", "bbt_unreferenced")]
            inv.carving = "background"
            from .inventory import CarvingJob
            inv.job = CarvingJob(inv, inv._known, inv.on_carved)
            inv.job.start()
        if wait:
            inv.job.wait(timeout)
        return list(inv.job.items)

    @property
    def carving(self):
        """The background :class:`~.inventory.CarvingJob` (``done``, ``wait()``,
        ``items``), or None."""
        return self.inventory.job if self.inventory is not None else None

    # -- random access ----------------------------------------------------
    def folder_paths(self) -> dict:
        """``{folder_nid: path}`` for every reachable folder (cached)."""
        if getattr(self, "_folder_paths", None) is None:
            inv = self.inventory
            if inv is not None and inv.folder_paths:
                self._folder_paths = dict(inv.folder_paths)
            else:
                from .inventory import Inventory
                tmp = Inventory(self, self.scan(), carving="skip")
                self._folder_paths = {f.nid: f.path for f in tmp._all_folders()}
                self._folder_paths.update(tmp.folder_paths)
        return self._folder_paths

    def item_index(self) -> list[dict]:
        """One structural record per item (state, provenance, NID/BID, folder
        NID, NBT entry) — from the cache when this store was enumerated
        before, else by enumerating now (carving included)."""
        inv = self.inventory
        if inv is not None and (inv.job is None or inv.job.done) and inv.complete:
            return list(inv.records)
        cache = self.nodedb.cache
        if cache is not None:
            recs = cache.load("items", (self.variant.name, bool(self.nodedb.nbt_damaged),
                                        False))
            if recs is not None:
                return recs
        for _ in self.iter_items():
            pass
        return list(self.inventory.records)

    def item(self, record: Optional[dict] = None, *, nid: Optional[int] = None,
             bid: Optional[int] = None):
        """Build one item from its index record (or by NID / carved BID) —
        reads only that message."""
        from .inventory import rebuild_item
        if record is None:
            for rec in self.item_index():
                if (nid is not None and rec["nid"] == nid and
                        rec["state"] in ("live", "live_damaged", "soft_deleted", "orphan")) or \
                        (bid is not None and rec["bid"] == bid):
                    record = rec
                    break
            else:
                return None
        return rebuild_item(self, record)

    def diagnostics(self) -> dict:
        """Content-free field report: environment, timings, failures by code
        location, warning codes, finding locations, scan/inventory stats."""
        from dataclasses import asdict
        from ..diagnostics import (environment, peak_rss_mb, rss_breakdown_mb,
                                   warnings_summary)
        hdr = self.nodedb.header
        locs: dict[str, list] = {}
        for f in self.integrity.findings:
            lst = locs.setdefault(f.code, [])
            if len(lst) < 5:
                lst.append({k: (f"{v:#x}" if isinstance(v, int) else v)
                            for k, v in (("ib", f.ib), ("bid", f.bid), ("nid", f.nid))
                            if v is not None})
        return {
            "environment": environment(),
            "file_size": self.nodedb.reader.size,
            "variant": self.variant.name, "wVer": hdr.wver,
            "crypt_method": hdr.crypt_method,
            "variant_evidence": hdr.variant_evidence,
            "nbt_damaged": self.nodedb.nbt_damaged,
            "bbt_damaged": self.nodedb.bbt_damaged,
            "btree_damage": self.nodedb.btree_damage(),
            "live_nbt_entries": len(self.nodedb._nbt),
            "live_bbt_entries": len(self.nodedb._bbt),
            "crypt_order": list(self.nodedb._block_reader.crypt_order),
            "crypt_verified_counts": dict(self.nodedb._block_reader.verified_counts),
            "store_findings": locs,
            "scan": asdict(self._scan.stats) if self._scan is not None else None,
            "scan_complete": self._scan.complete if self._scan is not None else None,
            "inventory": asdict(self.inventory_stats) if self.inventory_stats else None,
            "warnings": warnings_summary(self.sink),
            **self.diag.as_dict(),
            "peak_rss_mb": peak_rss_mb(),
            "rss_now_mb": rss_breakdown_mb(),
        }

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
        for tree, ibs in getattr(self.nodedb, "skipped", {}).items():
            for ib in ibs:
                integ.add(I.PAGE_UNREADABLE, f"{tree} page skipped (not a page)", ib=ib)
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


def open_store(source, *, sink: Optional[WarningSink] = None, progress=None,
               should_abort=None, cache_dir: Optional[str] = None,
               cache_key: Optional[str] = None) -> Store:
    """Open a PST/OST mail store and return its :class:`Store` (PLAN §6.1).

    Args:
        source: A path, ``bytes`` image, or seekable binary stream of a PST/OST.
        sink: Optional :class:`WarningSink`; one is created if omitted.
        progress: Optional ``progress(phase, done, total, found)`` called during
            the scan (``scan_pages``/``scan_blocks``, bytes) and the inventory
            (``folders``, ``live_items``, ``scan_items``, ``orphans``,
            ``carving``, ``lost_blocks``; ``total`` may be ``None``).  Counts
            only — never content.
        should_abort: Optional ``() -> bool`` polled by the scan.
        cache_dir: Directory for the persistent structural index (B-tree walk,
            scan, item index) — reopening the same store skips that work.
            Default: ``$PSTFORENSIC_CACHE_DIR``, else no cache.  Content-free.
        cache_key: The caller's content hash of the file (e.g. SHA-256) to key
            the cache with; default is a sampled content fingerprint.

    Returns:
        A :class:`Store` exposing ``root_folder``, ``folders()``, ``named_props``,
        ``nodedb`` and ``warnings``.

    Raises:
        NotAPstError: If the bytes are not a recognisable PST/OST store.
    """
    sink = sink if sink is not None else WarningSink()
    reader = FileReader(source, sink=sink)
    nodedb = NodeDatabase.open(reader, sink=sink, cache_dir=cache_dir,
                               cache_key=cache_key)
    return Store(nodedb, sink=sink, progress=progress, should_abort=should_abort)
