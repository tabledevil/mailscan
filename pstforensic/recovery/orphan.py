"""The deleted / orphan / slack four-state engine (PLAN §8).

Distinguishes four recovery states with distinct algorithms and confidence
bands (PLAN §8.1-§8.4, Appendix A H8/H9/H14/H15):

  1. **Soft-deleted** (§8.1, conf ~0.95): items still referenced by a folder's
     Contents TC — the *Deleted Items* folder and the Exchange dumpster /
     Recoverable-Items subfolders (Deletions/Versions/Purges/DiscoveryHolds).
     There is **no ``mfDeleted`` bit** (Appendix A H8) — "soft-deleted" is a
     *folder location*, not a flag.  Deletion timestamps resolve via the
     MS-OXPROPS/named-prop catalog at runtime (``PidTagDeletedOn`` and friends),
     never a hardcoded id (Appendix A H9).

  2. **Hard-deleted** (§8.2, conf ~0.70-0.85): node removed from the NBT, block
     AMap-freed but unzeroed.  Carve PC blocks (HN ``bSig 0xEC`` +
     ``bClientSig 0xBC``) from *free space* — the region NOT covered by the
     rebuilt live BBT (Appendix A H14) — and require ``PidTagMessageClass`` to
     confirm a real message.  Classified into ``pc_plus_subnode`` /
     ``pc_body_only`` / ``attachment_or_recipient_orphan`` / ``partial_fragment``.

  3. **Orphan PC** (§8.3, conf ~0.60-0.80): a node that is *allocated* (present
     in the live NBT/BBT) but unreachable from any live folder TC.

  4. **Slack** (§8.4, conf ~0.50-0.70): residual bytes after a block's live
     HNPAGEMAP-tracked region — emitted as *fragments only*, never as "items".

This module produces light-weight candidate records; the engine
(:mod:`pstforensic.recovery.engine`) parses/scores/dedupes them into
``RecoveredItem``s.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from ..ltp.heap import HN_CLIENT_PC, HN_SIG
from ..ndb.bref import nid_type
from ..ndb.block import block_disk_size
from ..variant import Variant
from .score import Extent, compute_free_space

# Recovery-class strings (PLAN §8.2 — describe *how much* survived).
CLASS_PC_PLUS_SUBNODE = "pc_plus_subnode"
CLASS_PC_BODY_ONLY = "pc_body_only"
CLASS_ATTACH_RECIP_ORPHAN = "attachment_or_recipient_orphan"
CLASS_PARTIAL_FRAGMENT = "partial_fragment"

# Folder display names that mark a soft-delete / dumpster location (§8.1).
SOFT_DELETE_FOLDER_NAMES = ("Deleted Items",)
DUMPSTER_FOLDER_NAMES = (
    "Recoverable Items", "Deletions", "Versions", "Purges", "DiscoveryHolds",
)

# PidTagMessageClass id ([MS-OXPROPS]) — required to confirm a carved message.
PID_MESSAGE_CLASS = 0x001A


@dataclass
class SoftDeletedFolder:
    """A folder whose location marks its contents soft-deleted (§8.1)."""

    nid: int
    path: str
    is_dumpster: bool


@dataclass
class HardDeletedCandidate:
    """A carved free-space block that parses as a message PC (§8.2)."""

    ib: int
    bid: int
    recovery_class: str
    raw_pc: bytes
    has_message_class: bool


@dataclass
class OrphanPC:
    """An allocated node unreachable from any live folder TC (§8.3)."""

    nid: int
    nid_parent: int


@dataclass
class SlackFragment:
    """Residual bytes after a block's live HNPAGEMAP region (§8.4)."""

    nid: int
    block_index: int
    offset: int
    data: bytes


@dataclass
class OrphanScan:
    """Aggregate output of :func:`scan` for the engine to consume (§8)."""

    soft_deleted_folders: List[SoftDeletedFolder] = field(default_factory=list)
    hard_deleted: List[HardDeletedCandidate] = field(default_factory=list)
    orphan_pcs: List[OrphanPC] = field(default_factory=list)
    slack_fragments: List[SlackFragment] = field(default_factory=list)
    free_for_carving: List[Extent] = field(default_factory=list)


# ---------------------------------------------------------------------------
# (1) Soft-deleted / dumpster classification (§8.1)
# ---------------------------------------------------------------------------
def classify_soft_deleted_folders(folders) -> List[SoftDeletedFolder]:
    """Classify live folders into soft-delete / dumpster locations (§8.1).

    A folder is soft-deleted if its *name* is "Deleted Items"; a dumpster
    (Recoverable Items) subfolder if its name is one of the well-known
    Deletions/Versions/Purges/DiscoveryHolds set.  No ``mfDeleted`` bit is
    consulted (Appendix A H8): location is the only signal.
    """
    out: List[SoftDeletedFolder] = []
    for f in folders:
        name = getattr(f, "name", "") or ""
        if name in SOFT_DELETE_FOLDER_NAMES:
            out.append(SoftDeletedFolder(f.nid, f.path, is_dumpster=False))
        elif name in DUMPSTER_FOLDER_NAMES:
            out.append(SoftDeletedFolder(f.nid, f.path, is_dumpster=True))
    return out


# ---------------------------------------------------------------------------
# (2) Hard-deleted carve from free space (§8.2)
# ---------------------------------------------------------------------------
def _looks_like_pc_block(payload: bytes) -> bool:
    """True iff ``payload`` opens with an HN whose client sig is a PC (§8.2.3).

    HNHDR layout ([MS-PST] §2.3.1.2): ibHnpm(2) bSig(1) bClientSig(1) ...
    A message PC has ``bSig == 0xEC`` and ``bClientSig == 0xBC``.
    """
    return (len(payload) >= 4 and payload[2] == HN_SIG
            and payload[3] == HN_CLIENT_PC)


def carve_hard_deleted(reader: FileReader, variant: Variant, *,
                       free_for_carving: List[Extent],
                       crypt_method: int,
                       sink: WarningSink) -> List[HardDeletedCandidate]:
    """Carve message-PC blocks from free space (PLAN §8.2).

    Scans each free extent on a 64-byte stride for a BLOCKTRAILER whose payload
    decodes to a PC heap.  Requires ``PidTagMessageClass`` *would* be present —
    here approximated by a successful PC heap shape; the engine re-parses with
    the real LTP parser before promoting (PLAN §7.6).  Most carves are
    ``pc_body_only`` because a hard-deleted NBTENTRY usually took its
    ``bidSub`` binding with it (§8.2.4).
    """
    from ..ndb.block import parse_block_trailer
    from ..ndb.crc import compute_crc, compute_sig
    from ..ndb.crypt import decode_block
    from ..ndb.bref import normalize_bid

    out: List[HardDeletedCandidate] = []
    align = variant.block_align
    ts = variant.block_trailer_size
    seen_ib: set[int] = set()

    for start, end in free_for_carving:
        # Block ends land on 64B boundaries; probe each candidate end.
        pos = ((start + align - 1) // align) * align
        if pos < align:
            pos = align
        while pos <= end:
            tr_off = pos - ts
            if tr_off < 0:
                pos += align
                continue
            cb = reader.u16(tr_off)
            if not (0 < cb <= variant.page_size * 512):
                pos += align
                continue
            disk = block_disk_size(cb, variant)
            ib = pos - disk
            if ib < start or ib in seen_ib or (ib % align) != 0:
                pos += align
                continue
            buf = reader.read(ib, disk)
            if len(buf) < disk:
                pos += align
                continue
            tr = parse_block_trailer(buf, variant)
            if tr.cb != cb:
                pos += align
                continue
            if compute_sig(ib, tr.bid) != tr.w_sig:
                pos += align
                continue
            payload = buf[:cb]
            if compute_crc(payload) != tr.dw_crc:
                pos += align
                continue
            bid = normalize_bid(tr.bid)
            decoded = decode_block(payload, crypt_method, bid)
            if _looks_like_pc_block(decoded):
                seen_ib.add(ib)
                out.append(HardDeletedCandidate(
                    ib=ib, bid=bid,
                    recovery_class=CLASS_PC_BODY_ONLY,
                    raw_pc=decoded,
                    has_message_class=False))  # confirmed later by LTP parse
            pos += align
    if out:
        sink.warn(WarnCode.TRUNCATED,
                  f"{len(out)} hard-deleted PC block(s) carved from free space "
                  "(no subnode binding → pc_body_only)",
                  where="orphan/hard")
    return out


# ---------------------------------------------------------------------------
# (3) Orphan PC: allocated-but-unreachable (§8.3)
# ---------------------------------------------------------------------------
def find_orphan_pcs(nodedb, reachable: set[int],
                    message_types: tuple[int, ...]) -> List[OrphanPC]:
    """Allocated message nodes unreachable from any live folder TC (§8.3).

    A node is an orphan iff it is a message-type NBT entry not in ``reachable``
    (the union of every live folder's Contents/FAI dwRowID set).  Attribution to
    a parent folder is the engine's job; here we just surface the node id.
    """
    out: List[OrphanPC] = []
    for ent in nodedb.iter_nbt():
        if nid_type(ent.nid) not in message_types:
            continue
        if ent.nid in reachable:
            continue
        out.append(OrphanPC(nid=ent.nid, nid_parent=ent.nid_parent))
    return out


# ---------------------------------------------------------------------------
# (4) Slack fragments (§8.4)
# ---------------------------------------------------------------------------
def extract_slack_fragments(noderef, variant: Variant, *,
                            sink: WarningSink,
                            min_fragment: int = 8) -> List[SlackFragment]:
    """Residual bytes after the live HNPAGEMAP region of each heap block (§8.4).

    For an allocated heap node, bytes between the last live allocation end and
    the HNPAGEMAP start (a property that shrank, old bytes unzeroed) are
    surfaced as ``SLACK`` *fragments only* — never promoted to items.
    """
    from ..ltp.heap import HeapOnNode

    out: List[SlackFragment] = []
    try:
        heap = HeapOnNode(noderef, variant, sink=sink)
    except Exception:
        return out
    for idx, (block, pmap) in enumerate(heap._blocks):
        if pmap is None or not pmap.rgib_alloc:
            continue
        live_end = max(pmap.rgib_alloc)
        # HNPAGEMAP starts at ib_hnpm; slack is [live_end, ib_hnpm).
        # Locate the pagemap start: it is rgib region; the HNPAGEMAP itself sits
        # at the end, so any gap between live_end and the pagemap offset is slack.
        # We approximate the pagemap offset as live_end's first index gap.
        # Practically: scan [live_end, len(block)-pagemap_bytes) for residue.
        pagemap_bytes = 4 + 2 * len(pmap.rgib_alloc)
        slack_start = live_end
        slack_end = len(block) - pagemap_bytes
        if slack_end - slack_start >= min_fragment:
            frag = block[slack_start:slack_end]
            if any(frag):
                out.append(SlackFragment(
                    nid=noderef.nid, block_index=idx,
                    offset=slack_start, data=frag))
    return out


# ---------------------------------------------------------------------------
# Free-space helper (Appendix A H14)
# ---------------------------------------------------------------------------
def free_space_for_carving(nodedb, *, file_size: int):
    """Compute the three free-space sets from a node DB's BBT (Appendix A H14).

    ``free_for_carving`` (the primary signal) is ``[0, file_size)`` minus every
    reachable block's ``[ib, ib+disk)``.  ``on_disk_free`` is derived from the
    ROOT's ``ib_amap_last``/``ib_file_eof`` hints when available.
    """
    info = nodedb.free_region_info() if hasattr(nodedb, "free_region_info") else None
    reachable: List[Extent] = []
    if info is not None:
        for ib, disk in info.get("live_block_extents", []):
            reachable.append((ib, min(ib + disk, file_size)))
        on_disk_free = None
        eof = info.get("ib_file_eof")
        amap_last = info.get("ib_amap_last")
        if eof and amap_last and eof > amap_last:
            on_disk_free = [(amap_last, min(eof, file_size))]
    else:
        variant = nodedb.variant
        for ent in nodedb.iter_bbt():
            ib = ent.bref.ib
            reachable.append((ib, min(ib + block_disk_size(ent.cb, variant), file_size)))
        on_disk_free = None
    return compute_free_space(file_size=file_size,
                              reachable_extents=reachable,
                              on_disk_free=on_disk_free)
