"""Store inventory — every message the file still holds, with state (PLAN §14.6).

``Store.items()`` merges the live folder walk with the full-file scan:

  * ``live`` / ``live_damaged`` — reached through a folder (damaged = findings).
  * ``soft_deleted`` — reached through Deleted Items / Recoverable Items.
  * ``orphan`` — in the live NBT but referenced by no folder.
  * ``deleted`` — NID absent from the live NBT; entry survives in a stale NBT
    page (``provenance="stale_page"``) or beyond ``cEnt`` (``"slack_slot"``).
  * ``superseded`` — an older, *different* version of a live or deleted item.
  * ``carved`` — a freed message PC block no entry references any more;
    taken only when signature ∧ CRC ∧ heap structure ∧ PidTagMessageClass
    hold, no other item uses the block and the content is new.
  * ``lost`` — only when the NBT itself is damaged: the newest on-disk entry
    of a NID no folder lists.  Deleted or cut off by the damage — undecidable.

Nodes a live folder still lists are live even when only the scan can place
them (``provenance="scan_nbt"``, finding ``NODE_FROM_SCAN``).

Identical stale copies are never items: same entry ⇒ counted by the scan;
same content under another parent ⇒ a ``moved`` entry in the live item's
``history``.  Unreferenced/unresolvable data never becomes a message unless it
parses as a message PC with ``PidTagMessageClass`` (PLAN §14.7).

Deletion metadata is only what the store records (PLAN §14.6): a PST keeps no
deletion log, so ``deleted_on`` comes solely from ``PidTagDeletedOn``; other
timestamps only bound the deletion from below (``not_before``).
"""
from __future__ import annotations

import hashlib
import struct
import time as _time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

from .. import integrity as I
from ..integrity import Integrity
from ..ltp.pc import PropertyContext
from ..ltp.tc import PID_LTP_ROW_ID, TableContext
from ..mapi import MapiMessage
from ..ndb.bref import (
    NID_ROOT_FOLDER,
    NID_TYPE_ASSOC_CONTENTS_TABLE,
    NID_TYPE_ASSOC_MESSAGE,
    NID_TYPE_CONTENTS_TABLE,
    NID_TYPE_NORMAL_FOLDER,
    NID_TYPE_NORMAL_MESSAGE,
    NID_TYPE_SEARCH_FOLDER,
    make_nid,
    nid_index,
    nid_type,
)
from ..ndb.scan import ScanIndex, ScannedSlot
from .message import build_message
import logging as _logging

_log = _logging.getLogger("pstforensic.inventory")

PID_MESSAGE_CLASS = 0x001A
PID_DISPLAY_NAME = 0x3001
PID_DELETED_ON = 0x668F
PID_LAST_MODIFIER_NAME = 0x3FFA
PID_IPM_WASTEBASKET_ENTRYID = 0x35E3
# Timestamps that bound a deletion from below, strongest last-touch first.
_NOT_BEFORE_PROPS = (
    (0x3008, "PidTagLastModificationTime"),
    (0x0E06, "PidTagMessageDeliveryTime"),
    (0x0039, "PidTagClientSubmitTime"),
    (0x3007, "PidTagCreationTime"),
)
_DUMPSTER_NAMES = ("recoverable items", "deletions", "versions", "purges",
                   "discoveryholds")
_MESSAGE_TYPES = (NID_TYPE_NORMAL_MESSAGE, NID_TYPE_ASSOC_MESSAGE)


@dataclass
class DeletionInfo:
    """What the store records about a deletion — each value with its source."""

    kind: str                                  # "soft" | "hard" | "orphan"
    original_folder: Optional[str] = None
    original_folder_nid: Optional[int] = None
    deleted_on: Optional[datetime] = None      # only PidTagDeletedOn
    deleted_on_source: Optional[str] = None
    modifier: Optional[str] = None
    modifier_source: Optional[str] = None
    not_before: Optional[datetime] = None      # lower bound only
    not_before_source: Optional[str] = None


@dataclass
class HistoryEntry:
    """A prior on-disk location of an item whose content is unchanged."""

    kind: str                     # "moved"
    nid_parent: int
    folder_path: Optional[str]
    page_ib: Optional[int]


@dataclass
class Item:
    """One message the store holds, with state, provenance and findings."""

    nid: int
    state: str
    provenance: str
    message: Optional[MapiMessage]
    folder_path: Optional[str]
    integrity: Integrity = field(default_factory=Integrity)
    deletion: Optional[DeletionInfo] = None
    history: list[HistoryEntry] = field(default_factory=list)
    supersedes: Optional[int] = None   # for superseded: the NID of the newer item
    copies: int = 1                    # identical on-disk copies collapsed
    bid: Optional[int] = None          # carved items: the PC block (no NID survives)
    entry: Optional[object] = field(default=None, repr=False)   # NBT entry used
    folder_nid: Optional[int] = None   # the folder that lists it (live items)
    _store: Optional[object] = field(default=None, repr=False, compare=False)

    def recover(self):
        """Deep salvage (PLAN §14.8) — see :func:`pstforensic.messaging.salvage.salvage`."""
        from .salvage import salvage
        return salvage(self._store, self)

    def record(self) -> dict:
        """Structural index record (no content): enough to rebuild the item
        with :meth:`Store.item` — what the persistent item index stores."""
        e = self.entry
        return {"state": self.state, "provenance": self.provenance, "nid": self.nid,
                "bid": self.bid, "folder_nid": self.folder_nid,
                "entry": (e.nid, e.bid_data, e.bid_sub, e.nid_parent) if e is not None else None}

    @property
    def parent_nid(self) -> Optional[int]:
        """The folder NID the item's NBT entry names (None for carved items)."""
        return getattr(self.entry, "nid_parent", None) or None

    @property
    def folder_label(self) -> str:
        """Where to show the item: its folder path, else a synthetic folder
        per parent NID (Kernel's orphan folders), else a bucket per state."""
        if self.folder_path:
            return self.folder_path
        if self.parent_nid:
            return f"/~orphan folders/folder {self.parent_nid:#x}"
        return f"/~{self.state}"

    @property
    def subject(self) -> Optional[str]:
        if self.message is None:
            return None
        v = self.message.render(0x0037)
        return v if isinstance(v, str) else None


@dataclass
class InventoryStats:
    unresolved_deleted: int = 0    # deleted entries whose data is gone/unparseable
    unresolved_stale: int = 0      # stale versions of live items unparseable
    identical_stale: int = 0       # stale copies identical to the live item
    carved_duplicates: int = 0     # carved PCs whose content another item has
    # Folder reconstruction (issue #3): check these before trusting orphans.
    folders_walked: int = 0
    contents_tables_missing: int = 0   # folder without a readable contents TC node
    folder_rows: int = 0               # valid rows (row id present) across tables
    folder_rows_duplicate: int = 0     # same child listed twice
    folder_rows_unresolved: int = 0    # row id with no node (NBT or scan)
    folder_rows_unreadable: int = 0    # node found, message not buildable
    orphans: int = 0                   # live NBT messages no folder lists
    lost_unreferenced: int = 0         # message PCs in live blocks no node reaches


def all_touched(ref) -> set[int]:
    """BIDs a node and its materialised subnodes read."""
    out = set(getattr(ref, "touched", ()))
    for child in (getattr(ref, "_subnodes", None) or {}).values():
        out |= all_touched(child)
    return out


class _CarvedRef:
    """A NodeRef stand-in for a single carved, already-decoded PC block."""

    def __init__(self, bid: int, plain: bytes, ib: int):
        self.nid = 0
        self.bid_data = bid
        self.bid_sub = 0
        self.nid_parent = 0
        self.touched = {bid}
        self.from_scan = True
        self._plain = plain
        self._ib = ib

    def data_stream(self) -> bytes:
        return self._plain

    def subnodes(self) -> dict:
        return {}

    def integrity(self, *, deep: bool = True) -> Integrity:
        integ = Integrity(level=I.CONSISTENT)
        integ.add(I.BLOCK_FROM_SCAN, bid=self.bid_data, ib=self._ib)
        integ.add(I.SUBNODES_UNKNOWN, "recipients/attachments not bound", bid=self.bid_data)
        return integ


def content_fingerprint(msg: MapiMessage) -> bytes:
    """SHA-256 over every property of the message, its recipients and attachments."""
    h = hashlib.sha256()

    def feed(obj, tag: bytes) -> None:
        h.update(tag)
        for t in sorted(obj.props):
            h.update(struct.pack("<I", t))
            raw = obj.props[t].raw or b""
            h.update(struct.pack("<I", len(raw)))
            h.update(raw)

    feed(msg, b"M")
    for r in msg.recipients:
        feed(r, b"R")
    for a in msg.attachments:
        feed(a, b"A")
    return h.digest()


def _render_time(msg: MapiMessage, prop_id: int) -> Optional[datetime]:
    try:
        v = msg.render(prop_id)
    except Exception:
        return None
    return v if isinstance(v, datetime) else None


def _render_text(msg: MapiMessage, prop_id: int) -> Optional[str]:
    try:
        v = msg.render(prop_id)
    except Exception:
        return None
    return v if isinstance(v, str) and v else None


def _deletion_info(msg: Optional[MapiMessage], kind: str,
                   folder: Optional[str], folder_nid: Optional[int]) -> DeletionInfo:
    info = DeletionInfo(kind=kind, original_folder=folder,
                        original_folder_nid=folder_nid)
    if msg is None:
        return info
    t = _render_time(msg, PID_DELETED_ON)
    if t is not None:
        info.deleted_on, info.deleted_on_source = t, "PidTagDeletedOn"
    m = _render_text(msg, PID_LAST_MODIFIER_NAME)
    if m is not None:
        info.modifier, info.modifier_source = m, "PidTagLastModifierName"
    for pid, name in _NOT_BEFORE_PROPS:
        t = _render_time(msg, pid)
        if t is not None and (info.not_before is None or t > info.not_before):
            info.not_before, info.not_before_source = t, name
    return info


class Inventory:
    """Builds :class:`Item` records for a :class:`~.store.Store`."""

    def __init__(self, store, scan: ScanIndex, *, include_fai: bool = False,
                 progress=None, should_abort=None, carving: str = "inline",
                 on_carved=None):
        self.store = store
        self.db = store.nodedb
        self.variant = store.variant
        self.sink = store.sink
        self.scan = scan
        self.include_fai = include_fai
        self._progress = progress
        self._should_abort = should_abort
        if carving not in ("inline", "background", "skip"):
            raise ValueError(f"carving must be inline/background/skip, not {carving!r}")
        self.carving = carving
        self.on_carved = on_carved
        self.records: list[dict] = []
        self.job: Optional["CarvingJob"] = None
        self.complete = False            # the structural stream was consumed
        self._known: set[bytes] = set()
        cache = getattr(self.db, "cache", None)
        self._carve_params = (self.variant.name, bool(self.db.nbt_damaged), include_fai)
        self._carve_only = cache.load("carving", self._carve_params) if cache else None
        self._carve_found: list[tuple[str, int]] = []
        self._carve_only_set = set(map(tuple, self._carve_only or ()))
        self.stats = InventoryStats()
        self.folder_paths: dict[int, str] = {}
        self.soft_folders: set[int] = set()
        self.reachable: set[int] = set()
        self.deleted_folder_names: dict[int, str] = {}
        self.history: dict[int, list[HistoryEntry]] = {}
        self.diag = getattr(store, "diag", None)
        self.last_fail: Optional[str] = None
        self.used_bids: set[int] = set()   # freed BIDs some item's read touched
        self._scan_bids = set(scan.blocks)
        # With NBT damage, live BBT blocks no surviving node references are
        # candidates too (their NBT entry sat on a lost page), so track all.
        self._track_all = bool(self.db.nbt_damaged)

    # -- helpers ----------------------------------------------------------
    def _message_types(self) -> tuple[int, ...]:
        return _MESSAGE_TYPES if self.include_fai else (NID_TYPE_NORMAL_MESSAGE,)

    def _tick(self, phase: str, done: int, total: Optional[int], found: int,
              *, force: bool = False) -> None:
        """Counts-only progress (issue #1): every completed check, incl. skips."""
        if self._progress is not None and (force or done % 256 == 0 or done == total):
            self._progress(phase, done, total, found)

    def _pc_block(self, raw: bytes, bid: int) -> Optional[bytes]:
        """Decoded block if it is the first block of a PC heap, else None.
        Decodes a 4-byte prefix first — the crypt methods are stream-wise,
        so the prefix decides almost every block without a full decode."""
        from ..ndb.block import looks_like_heap
        from ..ndb.crypt import decode_block
        if len(raw) < 16:
            return None
        for m in self.db._block_reader.crypt_order:
            head = decode_block(raw[:4], m, bid)
            if head[2] != 0xEC or head[3] != 0xBC:
                continue
            cand = decode_block(raw, m, bid)
            if looks_like_heap(cand):
                return cand
        return None

    def _build(self, ref) -> Optional[MapiMessage]:
        """Build a message, or return None and leave the cause in ``last_fail``
        (and, for exceptions, a content-free record in the diagnostics)."""
        self.last_fail = None
        try:
            msg = build_message(ref, self.variant, sink=self.sink,
                                renderer_installer=self.store.renderer_installer)
        except Exception as exc:
            self.last_fail = "exception"
            if self.diag is not None:
                self.diag.failure("build_message", exc, nid=getattr(ref, "nid", None),
                                  bid=getattr(ref, "bid_data", None))
            return None
        finally:
            # Only freed (scanned, non-live) blocks are carving candidates.
            t = all_touched(ref)
            self.used_bids |= t if self._track_all else (t & self._scan_bids)
        mclass = _render_text(msg, PID_MESSAGE_CLASS)
        if mclass is None:
            codes = msg.integrity.codes if msg.integrity is not None else set()
            self.last_fail = "block_missing" if "BLOCK_MISSING" in codes else "no_message_class"
            return None
        return msg

    def _note(self, what: str) -> None:
        if self.diag is not None:
            self.diag.reason(f"{what}:{self.last_fail}")

    def _folder_path(self, nid: int) -> Optional[str]:
        if nid in self.folder_paths:
            return self.folder_paths[nid]
        if nid in self.deleted_folder_names:
            return f"(deleted folder)/{self.deleted_folder_names[nid]}"
        return None

    def _slot_findings(self, slot: ScannedSlot) -> list:
        out = []
        ib = slot.entry.page_ib
        if not slot.page_crc_ok:
            out.append(I.Finding(I.PAGE_CRC_FAIL, ib=ib))
        if not slot.page_sig_ok:
            out.append(I.Finding(I.PAGE_SIG_FAIL, ib=ib))
        return out

    # -- live walk ----------------------------------------------------------
    def _wastebasket_nid(self) -> Optional[int]:
        pc = self.store.store_pc
        if pc is None:
            return None
        v = pc.by_id(PID_IPM_WASTEBASKET_ENTRYID)
        if v is None or not v.raw or len(v.raw) < 24:
            return None
        return struct.unpack_from("<I", v.raw, 20)[0]

    def _all_folders(self):
        """The IPM subtree first, then every other subtree of the store root
        (search roots, Freebusy Data, views …) under ``/~root``."""
        ipm = self.store.root_folder
        yield from self.store.folders()
        root_ref = self.db.node(NID_ROOT_FOLDER)
        if root_ref is None or (ipm is not None and ipm.nid == NID_ROOT_FOLDER):
            return
        try:
            pc = PropertyContext.from_node(root_ref, self.variant, sink=self.sink)
            self.store.renderer_installer(pc)
            from .folder import Folder
            root = Folder(self.store, pc, NID_ROOT_FOLDER, sink=self.sink,
                          noderef=root_ref)
            root.path = "/~root"
            self.folder_paths[NID_ROOT_FOLDER] = root.path
            for sub in root.subfolders():
                if ipm is not None and sub.nid == ipm.nid:
                    continue
                yield from sub.walk()
        except Exception as exc:
            if self.diag is not None:
                self.diag.failure("walk_non_ipm_folders", exc)
            return

    def _walk_live(self) -> list[tuple]:
        """Folder walk; returns ``[(folder, msg_nid)]`` and fills path maps."""
        waste = self._wastebasket_nid()
        pairs = []
        soft_roots: set[int] = set()
        for folder in self._all_folders():
            self.stats.folders_walked += 1
            self._tick("folders", self.stats.folders_walked, None,
                       self.stats.folder_rows, force=True)
            self.folder_paths[folder.nid] = folder.path
            parent_soft = any(folder.path.startswith(self.folder_paths[r] + "/")
                              for r in soft_roots)
            if (folder.nid == waste or folder.is_dumpster or parent_soft
                    or (waste is None and folder.name.lower() == "deleted items")):
                soft_roots.add(folder.nid)
                self.soft_folders.add(folder.nid)
            idx = nid_index(folder.nid)
            ttypes = [NID_TYPE_CONTENTS_TABLE]
            if self.include_fai:
                ttypes.append(NID_TYPE_ASSOC_CONTENTS_TABLE)
            for tt in ttypes:
                ref = self.db.node(make_nid(tt, idx))
                if ref is None:
                    if tt == NID_TYPE_CONTENTS_TABLE:
                        self.stats.contents_tables_missing += 1
                    continue
                for row in TableContext.from_node(ref, self.variant, sink=self.sink):
                    v = row.get_tag(PID_LTP_ROW_ID) or row.by_id(0x67F2)
                    if v is None or len(v.raw) < 4:
                        continue
                    nid = struct.unpack_from("<I", v.raw, 0)[0]
                    self.stats.folder_rows += 1
                    if nid in self.reachable:
                        self.stats.folder_rows_duplicate += 1
                        continue
                    self.reachable.add(nid)
                    pairs.append((folder, nid))
        return pairs

    # -- scan-derived -------------------------------------------------------
    def _collect_deleted_folders(self) -> None:
        for slot in self.scan.slots:
            ent = slot.entry
            if slot.variant != self.variant.name:
                continue
            if nid_type(ent.nid) not in (NID_TYPE_NORMAL_FOLDER, NID_TYPE_SEARCH_FOLDER):
                continue
            if ent.nid in self.folder_paths or ent.nid in self.deleted_folder_names:
                continue
            try:
                pc = PropertyContext.from_node(self.db.node_from_entry(ent),
                                               self.variant, sink=self.sink)
                raw = pc.by_id(PID_DISPLAY_NAME)
                name = raw.raw.decode("utf-16-le", "replace") if raw and raw.raw else None
            except Exception as exc:
                if self.diag is not None:
                    self.diag.failure("deleted_folder_name", exc, nid=ent.nid)
                name = None
            if name:
                self.deleted_folder_names[ent.nid] = name

    def _scan_items(self, only_nid: Optional[int] = None) -> Iterator[Item]:
        """Deleted and superseded items from the scan's non-live NBT slots."""
        live_nbt = self.db._nbt
        groups: dict[int, list[ScannedSlot]] = {}
        for slot in self.scan.slots:
            if slot.variant != self.variant.name:
                continue
            if only_nid is not None and slot.entry.nid != only_nid:
                continue
            if nid_type(slot.entry.nid) not in self._message_types():
                continue
            groups.setdefault(slot.entry.nid, []).append(slot)

        nbt_damaged = self.db.nbt_damaged
        for gi, (nid, slots) in enumerate(groups.items(), 1):
            self._tick("stale_items", gi, len(groups), 0)
            live_ent = live_nbt.get(nid)
            if live_ent is None and nid in self.reachable:
                live_ent = self.db.scan_entry(nid)   # listed by a folder: current
            newest = self.db.scan_entry(nid)
            live_fp = None
            if live_ent is not None:
                cur = (live_ent.bid_data, live_ent.bid_sub, live_ent.nid_parent)
                slots = [sl for sl in slots if (sl.entry.bid_data, sl.entry.bid_sub,
                                                sl.entry.nid_parent) != cur]
                if not slots:
                    continue
                live_msg = self._build(self.db.node(nid))
                live_fp = content_fingerprint(live_msg) if live_msg else None
            # Newest first: BIDs are allocated monotonically.
            versions: dict[bytes, list] = {}
            order: list[bytes] = []
            for slot in sorted(slots, key=lambda s: s.entry.bid_data, reverse=True):
                self.used_bids.update(b for b in (slot.entry.bid_data, slot.entry.bid_sub) if b)
                ref = self.db.node_from_entry(slot.entry)
                msg = self._build(ref)
                if msg is None:
                    if live_ent is None:
                        self.stats.unresolved_deleted += 1
                        self._note("unresolved_deleted")
                    else:
                        self.stats.unresolved_stale += 1
                        self._note("unresolved_stale")
                    continue
                fp = content_fingerprint(msg)
                if live_fp is not None and fp == live_fp:
                    if slot.entry.nid_parent != live_ent.nid_parent:
                        self.history.setdefault(nid, []).append(HistoryEntry(
                            "moved", slot.entry.nid_parent,
                            self._folder_path(slot.entry.nid_parent),
                            slot.entry.page_ib))
                    else:
                        self.stats.identical_stale += 1
                    continue
                if fp not in versions:
                    versions[fp] = []
                    order.append(fp)
                versions[fp].append((slot, ref, msg))

            newer = nid if live_ent is not None else None
            for i, fp in enumerate(order):
                slot, ref, msg = versions[fp][0]
                integ = Integrity()
                integ.extend(self._slot_findings(slot))
                if msg.integrity is not None:
                    integ.extend(msg.integrity.findings)
                parent = slot.entry.nid_parent
                folder = self._folder_path(parent)
                prov = "slack_slot" if slot.beyond_cent else "stale_page"
                if live_ent is None and i == 0:
                    lost = (nbt_damaged and slot.entry is newest and not slot.beyond_cent)
                    state = "lost" if lost else "deleted"
                    deletion = _deletion_info(msg, "unknown" if lost else "hard",
                                              folder, parent)
                    supersedes = None
                else:
                    state = "superseded"
                    deletion = None
                    supersedes = newer
                integ.level = I.INFERRED if state == "superseded" else I.CONSISTENT
                yield Item(nid=nid, state=state, provenance=prov, message=msg,
                           folder_path=folder, integrity=integ, deletion=deletion,
                           supersedes=supersedes, copies=len(versions[fp]),
                           entry=slot.entry)

    def _orphans(self) -> Iterator[Item]:
        total = len(self.db._nbt)
        for oi, ent in enumerate(self.db.iter_nbt(), 1):
            self._tick("orphans", oi, total, self.stats.orphans)
            if nid_type(ent.nid) not in self._message_types() or ent.nid in self.reachable:
                continue
            ref = self.db.node(ent.nid)
            msg = self._build(ref)
            if msg is None:
                self.stats.unresolved_deleted += 1
                self._note("unresolved_orphan")
                continue
            folder = self._folder_path(ent.nid_parent)
            integ = Integrity()
            if msg.integrity is not None:
                integ.extend(msg.integrity.findings)
            self.stats.orphans += 1
            yield Item(nid=ent.nid, state="orphan", provenance="btree", message=msg,
                       folder_path=folder, integrity=integ,
                       deletion=_deletion_info(msg, "orphan", folder, ent.nid_parent),
                       history=self.history.get(ent.nid, []), entry=ent)

    def _carved(self, known: set[bytes]) -> Iterator[Item]:
        """Freed message PC blocks that no surviving entry references."""
        total, found = len(self.scan.blocks), 0
        _log.info("carving: start (%d candidate block ids)", total)
        for done, (bid, copies) in enumerate(self.scan.blocks.items(), 1):
            self._tick("carving", done, total, found)
            if bid & 0x2 or bid in self.used_bids or bid in self.db._bbt:
                continue
            if self._carve_only is not None and ("carved", bid) not in self._carve_only_set:
                continue
            strong = [c for c in copies if c.strong and c.variant == self.variant.name]
            if not strong:
                continue
            blk = strong[0]
            plain = self._pc_block(self.db.reader.read(blk.ib, blk.cb), bid)
            if plain is None:
                continue
            msg = self._build(_CarvedRef(bid, plain, blk.ib))
            if msg is None:
                continue
            fp = content_fingerprint(msg)
            if fp in known:
                self.stats.carved_duplicates += 1
                continue
            known.add(fp)
            found += 1
            self._carve_found.append(("carved", bid))
            yield Item(nid=0, state="carved", provenance="free_space", message=msg,
                       folder_path=None, integrity=msg.integrity or Integrity(),
                       deletion=_deletion_info(msg, "hard", None, None), bid=bid)
        self._tick("carving", total, total, found, force=True)
        _log.info("carving: done (%d recovered)", found)
        if self._track_all:
            yield from self._unreferenced_live(known)

    def _unreferenced_live(self, known: set[bytes]) -> Iterator[Item]:
        """Message PCs in live BBT blocks that no surviving NBT entry reaches
        (the entry was on a lost NBT page) — Kernel's lost-item pass."""
        total, found = len(self.db._bbt), 0
        _log.info("lost_blocks: start (%d live block ids)", total)
        for done, (bid, ent) in enumerate(self.db._bbt.items(), 1):
            self._tick("lost_blocks", done, total, found)
            if bid & 0x2 or bid in self.used_bids:
                continue
            if self._carve_only is not None and ("lost", bid) not in self._carve_only_set:
                continue
            plain = self._pc_block(self.db.reader.read(ent.bref.ib, ent.cb), bid)
            if plain is None:
                continue
            msg = self._build(_CarvedRef(bid, plain, ent.bref.ib))
            if msg is None:
                continue
            fp = content_fingerprint(msg)
            if fp in known:
                self.stats.carved_duplicates += 1
                continue
            known.add(fp)
            found += 1
            self._carve_found.append(("lost", bid))
            self.stats.lost_unreferenced += 1
            yield Item(nid=0, state="lost", provenance="bbt_unreferenced", message=msg,
                       folder_path=None, integrity=msg.integrity or Integrity(),
                       deletion=None, bid=bid)
        self._tick("lost_blocks", total, total, found, force=True)
        _log.info("lost_blocks: done (%d recovered)", found)

    # -- public ---------------------------------------------------------------
    def items(self) -> Iterator[Item]:
        """Stream every item; only content hashes are retained (for carving
        dedup), so memory does not grow with the store."""
        known = self._known
        counts: dict[str, int] = {}
        _log.info("inventory: start")
        for it in self._chain(known):
            it._store = self.store
            counts[it.state] = counts.get(it.state, 0) + 1
            if _log.isEnabledFor(10):
                _log.debug("item nid=%#x bid=%s state=%s prov=%s folder_nid=%s codes=%s",
                           it.nid, f"{it.bid:#x}" if it.bid else "-", it.state,
                           it.provenance,
                           f"{it.entry.nid_parent:#x}" if it.entry is not None else "-",
                           sorted(it.integrity.codes))
            if sum(counts.values()) % 1000 == 0:
                _log.info("inventory: %d items so far %s", sum(counts.values()), counts)
            self.records.append(it.record())
            yield it
        _log.info("inventory: done %s stats=%s", counts, self.stats)
        self.complete = True
        if self.carving == "inline":
            self._finish()

    def _finish(self) -> None:
        """Everything enumerated: persist the carving result and item index."""
        cache = getattr(self.db, "cache", None)
        if cache is None or not self.scan.complete:
            return
        if self._carve_only is None:
            cache.save("carving", self._carve_found, self._carve_params)
        cache.save("items", self.records, self._carve_params)

    def _chain(self, known: set[bytes]) -> Iterator[Item]:
        for it in self._items():
            if it.message is not None:
                self._remember(known, it.message)
            yield it
        if self.carving == "inline":
            t = _time.perf_counter()
            yield from self._carved(known)
            self._add_time("carving", t)
        elif self.carving == "background":
            self.job = CarvingJob(self, known, self.on_carved)
            self.job.start()

    @staticmethod
    def _remember(known: set[bytes], msg) -> None:
        known.add(content_fingerprint(msg))
        for emb in msg.embedded_messages:   # e.g. recurring-meeting exceptions
            Inventory._remember(known, emb)

    def _timed(self, name: str):
        from contextlib import nullcontext
        return self.diag.timed(name) if self.diag is not None else nullcontext()

    def _items(self) -> Iterator[Item]:
        with self._timed("folder_walk"):
            pairs = self._walk_live()
            self._collect_deleted_folders()
        with self._timed("scan_items"):
            scan_items = list(self._scan_items())   # fills self.history first
        t_live = _time.perf_counter()
        for li, (folder, nid) in enumerate(pairs, 1):
            self._tick("live_items", li, len(pairs), li)
            ref = self.db.node(nid)
            if ref is None:
                self.stats.folder_rows_unresolved += 1
                if self.diag is not None:
                    self.diag.reason("live_listed_but_no_node")
                continue
            msg = self._build(ref)
            if msg is None:
                self.stats.folder_rows_unreadable += 1
                self._note("live_unreadable")
                continue
            integ = Integrity()
            integ.extend(folder.integrity.findings)
            if msg.integrity is not None:
                integ.extend(msg.integrity.findings)
            soft = folder.nid in self.soft_folders
            state = "soft_deleted" if soft else ("live_damaged" if not integ.ok else "live")
            integ.level = msg.integrity.level if msg.integrity is not None else integ.level
            yield Item(nid=nid, state=state,
                       provenance="scan_nbt" if ref.from_scan else "btree", message=msg,
                       folder_path=folder.path, integrity=integ,
                       deletion=_deletion_info(msg, "soft", None, None) if soft else None,
                       history=self.history.get(nid, []),
                       entry=self.db._nbt.get(nid) or self.db.scan_entry(nid),
                       folder_nid=folder.nid)
        self._add_time("live_items", t_live)
        t = _time.perf_counter()
        yield from self._orphans()
        self._add_time("orphans", t)
        yield from scan_items

    def _add_time(self, name: str, t0: float) -> None:
        """Wall time of a streamed phase (includes the consumer's time)."""
        if self.diag is not None:
            self.diag.timings[name] = round(self.diag.timings.get(name, 0.0)
                                            + _time.perf_counter() - t0, 3)


class CarvingJob:
    """Carving in a background thread (``iter_items(carving="background")``).

    Every recovered item is handed to ``on_item`` as soon as it is found (to
    trigger further examination) and collected in :attr:`items`.
    :meth:`wait` blocks until the carving index is complete.
    """

    def __init__(self, inv: Inventory, known: set, on_item=None):
        import threading
        self.inv = inv
        self.known = known
        self.on_item = on_item
        self.items: list[Item] = []
        self.error: Optional[str] = None
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._run, name="pstforensic-carving",
                                        daemon=True)

    def start(self) -> None:
        _log.info("carving: background job started")
        self._thread.start()

    def _run(self) -> None:
        t = _time.perf_counter()
        try:
            for it in self.inv._carved(self.known):
                it._store = self.inv.store
                self.items.append(it)
                self.inv.records.append(it.record())
                if self.on_item is not None:
                    try:
                        self.on_item(it)
                    except Exception as exc:   # a consumer hook never kills carving
                        if self.inv.diag is not None:
                            self.inv.diag.failure("on_carved_hook", exc, bid=it.bid)
            self.inv._finish()
        except Exception as exc:
            self.error = type(exc).__name__
            if self.inv.diag is not None:
                self.inv.diag.failure("carving_job", exc)
        finally:
            self.inv._add_time("carving", t)
            self._done.set()
            _log.info("carving: background job done (%d items)", len(self.items))

    @property
    def done(self) -> bool:
        return self._done.is_set()

    def wait(self, timeout: Optional[float] = None) -> bool:
        return self._done.wait(timeout)


def rebuild_item(store, rec: dict) -> Optional[Item]:
    """Rebuild one :class:`Item` from its index record, reading only it.

    History and supersession links come from a full enumeration and are not
    rebuilt; deletion info and findings are.
    """
    from ..ndb.btree import NBTEntry
    db = store.nodedb
    state, prov = rec["state"], rec["provenance"]
    ent = NBTEntry(*rec["entry"]) if rec.get("entry") else None
    if prov in ("free_space", "bbt_unreferenced"):
        bid = rec["bid"]
        if prov == "bbt_unreferenced":
            e = db._bbt.get(bid)
            loc = (e.bref.ib, e.cb) if e is not None else None
        else:
            loc = store.scan().locate(bid)
        if loc is None:
            return None
        inv = Inventory(store, store.scan(), carving="skip")
        plain = inv._pc_block(db.reader.read(loc[0], loc[1]), bid)
        if plain is None:
            return None
        msg = inv._build(_CarvedRef(bid, plain, loc[0]))
        kind = "hard" if state == "carved" else None
        folder = None
    else:
        ref = db.node_from_entry(ent) if ent is not None else db.node(rec["nid"])
        if ref is None:
            return None
        ref.from_scan = prov == "scan_nbt"
        msg = build_message(ref, store.variant, sink=store.sink,
                            renderer_installer=store.renderer_installer)
        paths = store.folder_paths()
        fnid = rec.get("folder_nid") or (ent.nid_parent if ent is not None else None)
        folder = paths.get(fnid) if fnid else None
        kind = {"soft_deleted": "soft", "orphan": "orphan", "deleted": "hard",
                "lost": None, "superseded": None}.get(state)
    if msg is None:
        return None
    integ = Integrity()
    if msg.integrity is not None:
        integ.extend(msg.integrity.findings)
        integ.level = msg.integrity.level
    deletion = _deletion_info(msg, kind, folder, ent.nid_parent if ent else None) \
        if kind else None
    it = Item(nid=rec["nid"], state=state, provenance=prov, message=msg,
              folder_path=folder,
              integrity=integ, deletion=deletion, bid=rec.get("bid"), entry=ent,
              folder_nid=rec.get("folder_nid"))
    it._store = store
    return it
