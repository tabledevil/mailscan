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
from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterator, Optional

from .. import integrity as I
from ..integrity import Integrity
from ..ltp.pc import PropertyContext
from ..ltp.tc import PID_LTP_ROW_ID, TableContext
from ..mapi import MapiMessage
from ..ndb.bref import (
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
    _store: Optional[object] = field(default=None, repr=False, compare=False)

    def recover(self):
        """Deep salvage (PLAN §14.8) — see :func:`pstforensic.messaging.salvage.salvage`."""
        from .salvage import salvage
        return salvage(self._store, self)

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

    def __init__(self, store, scan: ScanIndex, *, include_fai: bool = False):
        self.store = store
        self.db = store.nodedb
        self.variant = store.variant
        self.sink = store.sink
        self.scan = scan
        self.include_fai = include_fai
        self.stats = InventoryStats()
        self.folder_paths: dict[int, str] = {}
        self.soft_folders: set[int] = set()
        self.reachable: set[int] = set()
        self.deleted_folder_names: dict[int, str] = {}
        self.history: dict[int, list[HistoryEntry]] = {}
        self.used_bids: set[int] = set()   # every BID some item's read touched

    # -- helpers ----------------------------------------------------------
    def _message_types(self) -> tuple[int, ...]:
        return _MESSAGE_TYPES if self.include_fai else (NID_TYPE_NORMAL_MESSAGE,)

    def _build(self, ref) -> Optional[MapiMessage]:
        try:
            msg = build_message(ref, self.variant, sink=self.sink,
                                renderer_installer=self.store.renderer_installer)
        except Exception:
            return None
        finally:
            self.used_bids |= all_touched(ref)
        mclass = _render_text(msg, PID_MESSAGE_CLASS)
        if mclass is None:
            return None
        return msg

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

    def _walk_live(self) -> list[tuple]:
        """Folder walk; returns ``[(folder, msg_nid)]`` and fills path maps."""
        waste = self._wastebasket_nid()
        pairs = []
        soft_roots: set[int] = set()
        for folder in self.store.folders():
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
                    continue
                for row in TableContext.from_node(ref, self.variant, sink=self.sink):
                    v = row.get_tag(PID_LTP_ROW_ID) or row.by_id(0x6748)
                    if v is None or len(v.raw) < 4:
                        continue
                    nid = struct.unpack_from("<I", v.raw, 0)[0]
                    if nid in self.reachable:
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
            except Exception:
                name = None
            if name:
                self.deleted_folder_names[ent.nid] = name

    def _scan_items(self) -> Iterator[Item]:
        """Deleted and superseded items from the scan's non-live NBT slots."""
        live_nbt = self.db._nbt
        groups: dict[int, list[ScannedSlot]] = {}
        for slot in self.scan.slots:
            if slot.variant != self.variant.name:
                continue
            if nid_type(slot.entry.nid) not in self._message_types():
                continue
            groups.setdefault(slot.entry.nid, []).append(slot)

        nbt_damaged = self.db.nbt_damaged
        for nid, slots in groups.items():
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
                    else:
                        self.stats.unresolved_stale += 1
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
        for ent in self.db.iter_nbt():
            if nid_type(ent.nid) not in self._message_types() or ent.nid in self.reachable:
                continue
            ref = self.db.node(ent.nid)
            msg = self._build(ref)
            if msg is None:
                self.stats.unresolved_deleted += 1
                continue
            folder = self._folder_path(ent.nid_parent)
            integ = Integrity()
            if msg.integrity is not None:
                integ.extend(msg.integrity.findings)
            yield Item(nid=ent.nid, state="orphan", provenance="btree", message=msg,
                       folder_path=folder, integrity=integ,
                       deletion=_deletion_info(msg, "orphan", folder, ent.nid_parent),
                       history=self.history.get(ent.nid, []), entry=ent)

    def _carved(self, known: set[bytes]) -> Iterator[Item]:
        """Freed message PC blocks that no surviving entry references."""
        from ..ndb.block import looks_like_heap
        from ..ndb.crypt import decode_block
        br = self.db._block_reader
        for bid, copies in self.scan.blocks.items():
            if bid & 0x2 or bid in self.used_bids or bid in self.db._bbt:
                continue
            strong = [c for c in copies if c.strong and c.variant == self.variant.name]
            if not strong:
                continue
            blk = strong[0]
            raw = self.db.reader.read(blk.ib, blk.cb)
            plain = None
            for m in br.crypt_order:
                cand = decode_block(raw, m, bid)
                if looks_like_heap(cand) and cand[3] == 0xBC:
                    plain = cand
                    break
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
            yield Item(nid=0, state="carved", provenance="free_space", message=msg,
                       folder_path=None, integrity=msg.integrity or Integrity(),
                       deletion=_deletion_info(msg, "hard", None, None), bid=bid)

    # -- public ---------------------------------------------------------------
    def items(self) -> Iterator[Item]:
        produced = list(self._items())
        known = {content_fingerprint(i.message) for i in produced if i.message is not None}
        produced.extend(self._carved(known))
        for it in produced:
            it._store = self.store
        return iter(produced)

    def _items(self) -> Iterator[Item]:
        pairs = self._walk_live()
        self._collect_deleted_folders()
        scan_items = list(self._scan_items())   # fills self.history first
        for folder, nid in pairs:
            ref = self.db.node(nid)
            if ref is None:
                continue
            msg = self._build(ref)
            if msg is None:
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
                       entry=self.db._nbt.get(nid) or self.db.scan_entry(nid))
        yield from self._orphans()
        yield from scan_items
