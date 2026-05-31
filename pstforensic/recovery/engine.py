"""Recovery cascade — surface deleted/orphaned items (PLAN §7 / §8).

The :class:`RecoveryEngine` runs the recovery cascade described in the design
([PLAN] §7.1 "trusted walk first") and the deleted/orphan engine ([PLAN] §8.2):

  * **Stage 0 — trusted walk.**  Open the live store (the same bootstrap
    :func:`pstforensic.messaging.store.open_store` uses) and collect the set of
    *reachable* message NIDs: every ``dwRowID`` found in a live folder's
    contents / FAI (associated-contents) Table Context ([MS-PST] §2.4.4.5).

  * **Stage 1 — reachability diff (orphan / hard-delete detection).**  Walk the
    rebuilt NBT for every normal-message node (``nidType 0x04``) and every
    associated-message node (``nidType 0x08``).  Any such node **not** reached by
    the trusted walk is a *deleted / orphaned* message whose NBT entry survived
    but which no folder references — recoverable, envelope+body intact
    ([PLAN] §8.2 ``pc_plus_subnode`` / ``pc_body_only``).

Each surfaced item is parsed into a :class:`~pstforensic.mapi.MapiMessage`,
attributed to its (claimed) parent folder via ``nid_parent`` ([MS-PST]
§2.2.2.7.7.4), and confidence-scored with the documented weighted-signal model
in :mod:`pstforensic.recovery.score` (PLAN §7.7).  Confidence is **honest**: a
hard-deleted item is banded below a live tree item (Appendix A H15).

Free space (the carving source for *hard*-deleted blocks whose NBT entry is
gone) is computed via :func:`pstforensic.recovery.score.compute_free_space` and
is "NOT covered by the rebuilt live BBT" — never the AMap XOR (Appendix A H14).

This implementation covers the trusted-walk and reachability-diff stages with
test vectors.  Deeper cascade stages (signature carving of blocks whose NBT
entry is *also* gone, BBT/NBT rebuild from page signatures, and encode brute
force) are not yet implemented; the free-space algebra they would scan is
provided by :func:`pstforensic.recovery.score.compute_free_space`.  See
``STATUS.md`` for the honest gap analysis.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from ..mapi import MapiMessage
from ..ndb.bref import (
    NID_TYPE_ASSOC_MESSAGE,
    NID_TYPE_CONTENTS_TABLE,
    NID_TYPE_ASSOC_CONTENTS_TABLE,
    NID_TYPE_NORMAL_MESSAGE,
    make_nid,
    nid_index,
    nid_type,
)
from ..ndb.nodedb import NodeDatabase
from ..messaging.message import build_message
from ..messaging.store import Store
from .. import render
from .carve import carve
from .dedup import dedup
from .encode_detect import detect_encode_method
from .orphan import (
    CLASS_PC_BODY_ONLY,
    PID_MESSAGE_CLASS,
    carve_hard_deleted,
    free_space_for_carving,
)
from .rebuild import RebuiltNodeDatabase, rebuild_index
from .score import RecoveryMeta, Signals, score_confidence

# Confidence bands applied per recovery method (PLAN §7.7 / §8).
from .score import (
    BAND_HARD_MAX,
    BAND_HARD_MIN,
    BAND_ORPHAN_MAX,
    BAND_ORPHAN_MIN,
)

# PidTag ids used for provenance/attribution (resolved at runtime — Appendix A
# H9: never hardcode an id we cannot cite).
PID_SUBJECT = 0x0037                 # PidTagSubject ([MS-OXPROPS])
PID_DELETED_ON = 0x668F              # PidTagDeletedOn (FILETIME, [MS-OXPROPS])
PID_MESSAGE_DELIVERY = 0x0E06        # PidTagMessageDeliveryTime
PID_DISPLAY_NAME = 0x3001            # PidTagDisplayName (folder name)


@dataclass
class RecoveredItem:
    """One recovered (deleted/orphaned) item with provenance (PLAN §8.5).

    Attributes:
        nid: The recovered node's NID.
        message: The parsed :class:`MapiMessage` (envelope/body/recipients as far
            as survived), or ``None`` if even the PC could not be parsed.
        meta: The :class:`RecoveryMeta` provenance + confidence record.
        subject: Convenience copy of the rendered ``PidTagSubject`` (or ``None``).
    """

    nid: int
    message: Optional[MapiMessage]
    meta: RecoveryMeta
    subject: Optional[str] = None


class _StandaloneNodeRef:
    """A minimal :class:`NodeRef`-shaped wrapper over a single decoded block.

    Used to hand a carved (already-decoded) data block to the unchanged LTP
    parser for cross-validation (PLAN §7.6).  It exposes ``data_stream()`` (the
    decoded bytes verbatim) and an empty ``subnodes()`` map — a hard-deleted
    carve usually lost its subnode binding (Appendix A §8.2.4), so recipients /
    attachments are not recoverable, and the item lands as ``pc_body_only``.
    """

    def __init__(self, db, bid: int, decoded: bytes) -> None:
        self.nid = bid
        self.bid_data = bid
        self.bid_sub = 0
        self.nid_parent = 0
        self._db = db
        self._decoded = decoded

    def data_stream(self) -> bytes:
        """Return the carved block's already-decoded bytes."""
        return self._decoded

    def subnodes(self) -> dict:
        """No subnode tree survived the hard delete (Appendix A §8.2.4)."""
        return {}


class RecoveryEngine:
    """Run the recovery cascade over a PST/OST source (CONTRACTS §"recovery").

    Args:
        source: A path, ``bytes`` image, or seekable binary stream of a PST/OST.
        sink: Optional :class:`WarningSink`; one is created if omitted.
    """

    def __init__(self, source, *, sink: Optional[WarningSink] = None) -> None:
        self.sink = sink if sink is not None else WarningSink()
        self._reader = FileReader(source, sink=self.sink)
        self.nodedb = NodeDatabase.open(self._reader, sink=self.sink)
        self.variant = self.nodedb.variant
        # The live store gives us the trusted folder walk (Stage 0).  A bootstrap
        # failure (no message store) is non-fatal for recovery: we degrade to a
        # pure NBT reachability scan with an empty reachable set.
        try:
            self._store: Optional[Store] = Store(self.nodedb, sink=self.sink)
        except Exception:  # pragma: no cover - defensive; bootstrap is tolerant
            self._store = None
        # Roots are "broken" when the trusted NBT/BBT walk reached (almost)
        # nothing — a truncated tail, a zeroed/garbage ROOT BREF, or a dropped
        # root page.  That is the trigger for the carve→rebuild fallback (§7.2).
        self._roots_broken = self._detect_broken_roots()

    def _detect_broken_roots(self) -> bool:
        """True iff the trusted B-tree walk failed to reach a usable NBT (§7.2).

        Heuristic: an empty NBT, or a header whose CRC/structure shows truncation
        (the BBT/NBT live at the tail, so a half-file ``truncate`` wipes them).
        A healthy synthetic/real store always has a populated NBT here.
        """
        nbt_count = sum(1 for _ in self.nodedb.iter_nbt())
        bbt_count = sum(1 for _ in self.nodedb.iter_bbt())
        if nbt_count == 0 or bbt_count == 0:
            return True
        # A claimed EOF past the actual file size means the tail (and thus some
        # B-tree pages) was truncated even if a few entries survived.
        eof = self.nodedb.header.root.ib_file_eof
        if eof and eof > self._reader.size:
            return True
        return False

    # -- public surface ---------------------------------------------------
    def recover(self) -> List[RecoveredItem]:
        """Run the FULL recovery cascade and return recovered items (PLAN §7/§8).

        Cascade ordering:
          0. trusted walk (Stage 0) — collect live + orphan/deleted NBT nodes;
          1. if roots are broken/truncated → carve → rebuild → encode-detect,
             then re-run the orphan diff over the rebuilt NBT;
          2. hard-deleted carve from free space (Appendix A H14);
          3. orphan-PC + soft-deleted classification.
        Results merge through :func:`dedup` (PLAN §8.6), each item carrying a
        :class:`RecoveryMeta` provenance/confidence record.
        """
        # Stage 0: trusted walk over the (possibly degraded) live DB.
        folders = self._live_folders()
        reachable = self._reachable_message_nids(folders)
        folder_names = {f.nid: f.path for f in folders}

        out: List[RecoveredItem] = []
        out.extend(self._orphan_diff(self.nodedb, reachable, folder_names))

        # Stages 1-2: fallback cascade when the trusted roots are broken.
        if self._roots_broken:
            out.extend(self._cascade_rebuild(folder_names))
        else:
            # Healthy roots: an allocated block can still be unreachable from any
            # NBT node (its NBTENTRY was dropped) → orphan PC (§8.3); and the
            # genuinely free space can hold AMap-freed unzeroed blocks (§8.2).
            out.extend(self._cascade_orphan_blocks(folder_names))
            out.extend(self._cascade_hard_deleted(self.nodedb, folder_names))

        return dedup(out)

    # -- Stage 3: orphan-PC detection (allocated-but-unreferenced, §8.3) ---
    def _cascade_orphan_blocks(self,
                               folder_names: dict[int, str]) -> List[RecoveredItem]:
        """Recover message PCs in allocated blocks no NBT node references (§8.3).

        Builds the set of block BIDs referenced by any live NBT node (as
        ``bidData`` or ``bidSub``); any *data* block in the BBT outside that set
        is parsed as a PC and promoted iff it carries an ``IPM.*``
        ``PidTagMessageClass`` (rejecting live subnode PCs — PLAN §7.6).
        """
        from ..ndb.crypt import decode_block
        from .orphan import _looks_like_pc_block

        referenced: set[int] = set()
        for ent in self.nodedb.iter_nbt():
            for bid in (ent.bid_data, ent.bid_sub):
                if bid:
                    referenced.add(bid)

        out: List[RecoveredItem] = []
        for bbt in self.nodedb.iter_bbt():
            bid = bbt.bid
            if bid in referenced or (bid & 0x2):
                continue  # referenced, or an internal (XBLOCK/SLBLOCK) block
            raw = self.nodedb._block_reader.read_raw(bid)
            if raw is None:
                continue
            decoded = decode_block(raw, self.nodedb.crypt_method, bid)
            if not _looks_like_pc_block(decoded):
                continue
            item = self._parse_orphan_pc(bid, decoded)
            if item is not None:
                out.append(item)
        return out

    def _parse_orphan_pc(self, bid: int, decoded: bytes) -> Optional[RecoveredItem]:
        """Parse an unreferenced allocated PC block as an orphan message (§8.3)."""
        ref = _StandaloneNodeRef(self, bid, decoded)
        try:
            msg = build_message(ref, self.variant, sink=self.sink,
                                renderer_installer=render.install_renderer)
        except Exception:
            return None
        mclass = msg.render(PID_MESSAGE_CLASS)
        if not (isinstance(mclass, str) and mclass.startswith("IPM")):
            return None  # not a top-level message (live subnode PC, etc.)
        subject = self._render_str(msg, PID_SUBJECT)
        signals = Signals(tree_reached=False, block_crc_ok=True,
                          page_sig_ok=True, parent_resolves=False,
                          ltp_pc_ok=True, cref_ok=True, not_slack=True)
        conf = max(BAND_ORPHAN_MIN, min(BAND_ORPHAN_MAX, score_confidence(signals)))
        meta = RecoveryMeta(
            method="orphan_pc",
            confidence=conf,
            attributed_folder="LostAndFound",
            attribution_confidence=0.2,
            recovery_class=CLASS_PC_BODY_ONLY,
            truncated=False,
            flags=set(),
            raw_pc=decoded,
        )
        return RecoveredItem(nid=bid, message=msg, meta=meta, subject=subject)

    # -- Stage 0/3: orphan reachability diff over a node DB ----------------
    def _orphan_diff(self, nodedb, reachable: set[int],
                     folder_names: dict[int, str]) -> List[RecoveredItem]:
        """Surface message nodes present in ``nodedb`` but not ``reachable``."""
        out: List[RecoveredItem] = []
        for ent in nodedb.iter_nbt():
            nt = nid_type(ent.nid)
            if nt not in (NID_TYPE_NORMAL_MESSAGE, NID_TYPE_ASSOC_MESSAGE):
                continue
            if ent.nid in reachable:
                continue  # live item — owned by a folder, not deleted
            out.append(self._recover_one(nodedb, ent.nid, ent.nid_parent,
                                         folder_names))
        return out

    # -- Stage 1: carve → rebuild → encode-detect fallback -----------------
    def _cascade_rebuild(self, folder_names: dict[int, str]) -> List[RecoveredItem]:
        """Carve+rebuild the NBT/BBT when trusted roots are broken (§7.2-§7.5)."""
        self.sink.warn(WarnCode.TRUNCATED,
                       "trusted ROOT B-tree unusable; entering carve fallback",
                       where="recovery/cascade")
        carved = carve(self._reader, self.variant, sink=self.sink)
        index = rebuild_index(carved, sink=self.sink)

        # Encode-detect on a probe data block (a node whose data is present).
        crypt_method = self.nodedb.crypt_method
        probe = self._probe_block(index)
        if probe is not None:
            guess = detect_encode_method(probe[1], probe[0], sink=self.sink)
            if guess is not None and guess.hn_sig_ok:
                crypt_method = guess.crypt_method

        out: List[RecoveredItem] = []
        carved_nids: set[int] = set()
        if index.nbt:
            rebuilt = RebuiltNodeDatabase(
                self._reader, self.variant, index=index,
                crypt_method=crypt_method, sink=self.sink)
            # The rebuilt DB has no trusted folder walk; every message node is a
            # recovery candidate (nothing reachable through a live folder TC).
            items = self._orphan_diff(rebuilt, reachable=set(),
                                      folder_names=folder_names)
            for it in items:
                # Carve-rebuilt items are NOT btree-trusted (AC-2).
                if it.meta.method == "btree":
                    it.meta.method = "carve_hard"
                    it.meta.flags.add(WarnCode.TRUNCATED)
                carved_nids.add(it.nid)
            out.extend(items)

        # Whatever the rebuilt NBT did not bind, recover by carving the surviving
        # data blocks as hard-deleted PCs directly (free space = the whole file
        # minus the rebuilt BBT — Appendix A H14).  This is the survivor-prefix
        # path when the NBT/BBT pages were truncated away entirely (AC-2).
        out.extend(self._carve_surviving_pcs(carved, crypt_method, folder_names))
        return out

    def _carve_surviving_pcs(self, carved, crypt_method: int,
                             folder_names: dict[int, str]) -> List[RecoveredItem]:
        """Promote carved data blocks that parse as message PCs (§7.6/§8.2).

        Each carved block whose decoded payload opens with an HN PC signature
        (``bSig 0xEC`` / ``bClientSig 0xBC``) is cross-validated by the real LTP
        PC parser; only a PC carrying ``PidTagMessageClass`` is promoted to an
        item (PLAN §7.6 rejects false positives).
        """
        from ..ndb.crypt import decode_block
        from .orphan import _looks_like_pc_block

        out: List[RecoveredItem] = []
        for blk in carved.blocks:
            if blk.bid & 0x2:  # internal block — not a leaf PC
                continue
            decoded = decode_block(blk.payload, crypt_method, blk.bid)
            if not _looks_like_pc_block(decoded):
                continue
            item = self._parse_carved_pc(blk, decoded)
            if item is not None:
                out.append(item)
        return out

    def _parse_carved_pc(self, blk, decoded: bytes) -> Optional[RecoveredItem]:
        """Cross-validate a carved PC block via the real LTP parser (§7.6)."""
        ref = _StandaloneNodeRef(self, blk.bid, decoded)
        try:
            msg = build_message(ref, self.variant, sink=self.sink,
                                renderer_installer=render.install_renderer)
        except Exception:
            return None
        # Require PidTagMessageClass (IPM.*) to confirm a real message (§8.2.3).
        mclass = msg.render(PID_MESSAGE_CLASS)
        if not (isinstance(mclass, str) and mclass.startswith("IPM")):
            return None
        subject = self._render_str(msg, PID_SUBJECT)
        signals = Signals(tree_reached=False, block_crc_ok=blk.crc_ok,
                          page_sig_ok=False, parent_resolves=False,
                          ltp_pc_ok=True, cref_ok=True, not_slack=True)
        conf = max(BAND_HARD_MIN, min(BAND_HARD_MAX, score_confidence(signals)))
        meta = RecoveryMeta(
            method="carve_hard",
            confidence=conf,
            attributed_folder="LostAndFound",
            attribution_confidence=0.2,
            recovery_class=CLASS_PC_BODY_ONLY,
            truncated=True,
            flags={WarnCode.TRUNCATED},
            raw_pc=decoded,
        )
        return RecoveredItem(nid=blk.bid, message=msg, meta=meta, subject=subject)

    def _probe_block(self, index) -> Optional[tuple[int, bytes]]:
        """Pick one carved data block to probe the encode method (§7.5)."""
        for bid, ent in index.bbt.items():
            if bid & 0x2:  # internal block (XBLOCK/SLBLOCK) — skip
                continue
            from ..ndb.block import block_disk_size
            disk = block_disk_size(ent.cb, self.variant)
            buf = self._reader.read(ent.bref.ib, disk)
            if len(buf) >= disk:
                return bid, buf[:ent.cb]
        return None

    # -- Stage 2: hard-deleted carve from free space (§8.2) ----------------
    def _cascade_hard_deleted(self, nodedb,
                              folder_names: dict[int, str]) -> List[RecoveredItem]:
        """Carve hard-deleted message PCs from free space (Appendix A H14)."""
        free = free_space_for_carving(nodedb, file_size=self._reader.size)
        cands = carve_hard_deleted(
            self._reader, self.variant,
            free_for_carving=free.free_for_carving,
            crypt_method=nodedb.crypt_method, sink=self.sink)
        out: List[RecoveredItem] = []
        for c in cands:
            out.append(self._recover_carved(c, folder_names))
        return out

    def _recover_carved(self, cand, folder_names: dict[int, str]) -> RecoveredItem:
        """Wrap a hard-deleted carved PC block into a :class:`RecoveredItem`."""
        meta = RecoveryMeta(
            method="carve_hard",
            confidence=BAND_HARD_MIN,
            attributed_folder="LostAndFound",
            attribution_confidence=0.2,
            recovery_class=cand.recovery_class,
            truncated=True,
            flags={WarnCode.TRUNCATED},
            raw_pc=cand.raw_pc,
        )
        return RecoveredItem(nid=cand.bid, message=None, meta=meta, subject=None)

    # -- Stage 0: trusted walk -------------------------------------------
    def _live_folders(self) -> list:
        """Snapshot the live folder tree (root first), or ``[]`` (PLAN §7.1)."""
        if self._store is None or self._store.root_folder is None:
            return []
        return list(self._store.folders())

    def _reachable_message_nids(self, folders: list) -> set[int]:
        """Collect every message NID referenced by a live folder (PLAN §7.1).

        Unions each folder's contents-TC and FAI-TC ``dwRowID`` values
        ([MS-PST] §2.4.4.5).  Returns the set of NIDs a trusted top-down walk
        reaches; everything else is orphaned.
        """
        reachable: set[int] = set()
        from ..ltp.tc import TableContext, PID_LTP_ROW_ID
        import struct

        for folder in folders:
            idx = nid_index(folder.nid)
            for ttype in (NID_TYPE_CONTENTS_TABLE, NID_TYPE_ASSOC_CONTENTS_TABLE):
                ref = self.nodedb.node(make_nid(ttype, idx))
                if ref is None:
                    continue
                for row in TableContext.from_node(ref, self.variant, sink=self.sink):
                    v = row.get_tag(PID_LTP_ROW_ID) or row.by_id(0x6748)
                    if v is None or len(v.raw) < 4:
                        continue
                    reachable.add(struct.unpack_from("<I", v.raw, 0)[0])
        return reachable

    # -- per-item recovery -------------------------------------------------
    def _recover_one(self, nodedb, nid: int, nid_parent: int,
                     folder_names: dict[int, str]) -> RecoveredItem:
        """Parse and score one orphaned message node (PLAN §8.2 / §7.7)."""
        ref = nodedb.node(nid)
        message: Optional[MapiMessage] = None
        subject: Optional[str] = None
        deleted_on: Optional[datetime] = None
        deleted_on_source: Optional[str] = None
        truncated = False
        signals = Signals(
            tree_reached=False,        # by definition NOT in the trusted walk
            block_crc_ok=True,         # NBT/BBT walk validated the block trailer
            page_sig_ok=True,
            parent_resolves=nid_parent in folder_names,
            cref_ok=True,
            not_slack=True,            # NBT entry intact → not in slack
        )
        recovery_class = "pc_body_only"
        raw_pc: Optional[bytes] = None

        if ref is not None:
            try:
                raw_pc = ref.data_stream()
            except Exception:
                raw_pc = None
            try:
                message = build_message(
                    ref, self.variant, sink=self.sink,
                    renderer_installer=render.install_renderer)
                signals.ltp_pc_ok = True
                if ref.bid_sub:
                    recovery_class = "pc_plus_subnode"
                subject = self._render_str(message, PID_SUBJECT)
                # Provenance: a deletion timestamp if the item carries one (H9).
                dval = message.render(PID_DELETED_ON)
                if isinstance(dval, datetime):
                    deleted_on, deleted_on_source = dval, "PidTagDeletedOn"
                elif isinstance(message.render(PID_MESSAGE_DELIVERY), datetime):
                    deleted_on = message.render(PID_MESSAGE_DELIVERY)
                    deleted_on_source = "PidTagMessageDeliveryTime"
            except Exception:
                truncated = True
                self.sink.warn(WarnCode.TRUNCATED,
                               f"orphan message {nid:#x} PC unparseable",
                               where="recovery")
        else:
            truncated = True

        attributed = folder_names.get(nid_parent, "LostAndFound")
        attribution_conf = 0.8 if nid_parent in folder_names else 0.2

        meta = RecoveryMeta(
            method="btree",
            confidence=score_confidence(signals),
            deleted_on=deleted_on,
            deleted_on_source=deleted_on_source,
            attributed_folder=attributed,
            attribution_confidence=attribution_conf,
            recovery_class=recovery_class,
            truncated=truncated,
            flags={WarnCode.OUT_OF_BOUNDS} if truncated else set(),
            raw_pc=raw_pc,
        )
        return RecoveredItem(nid=nid, message=message, meta=meta, subject=subject)

    # -- helpers ----------------------------------------------------------
    @staticmethod
    def _render_str(message: MapiMessage, prop_id: int) -> Optional[str]:
        """Render a string property to text, or ``None`` if absent/non-string."""
        val = message.render(prop_id)
        return val if isinstance(val, str) and val else None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"RecoveryEngine(variant={self.variant.name})"
