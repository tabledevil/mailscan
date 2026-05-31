"""Index rebuild from carved entries (PLAN §7.3 / §7.4).

Takes a :class:`~pstforensic.recovery.carve.CarveResult` and reconstructs the
NBT/BBT indexes the trusted walk could not reach:

  * ``bbt_rebuilt: dict[bid -> BBTEntry]`` — from carved BBTENTRYs, deduped by
    BID (prefer the entry whose block actually trailer-validates).
  * ``nbt_rebuilt: dict[nid -> NBTEntry]`` — from carved NBTENTRYs.
  * Dangling ``bidData``/``bidSub`` (referenced by an NBTENTRY but absent from
    the rebuilt BBT) are recorded but the node is kept (``DANGLING_BID``).

A :class:`RebuiltNodeDatabase` then exposes the *same* surface the LTP/messaging
tiers consume from :class:`~pstforensic.ndb.nodedb.NodeDatabase`
(``node(nid)``, ``iter_nbt()``, ``iter_bbt()``, ``variant``, ``crypt_method``)
so carved nodes can be handed to the real PC/TC parser (PLAN §7.6 cross-check).

AMap reconstruction (:func:`reconstruct_amap`) is **in-memory / advisory only**
([MS-PST] §2.6.1.3.7, Appendix A N1): it never writes the evidence file.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterator, List, Optional

from ..exceptions import WarnCode, WarningSink
from ..fileio import FileReader
from ..ndb.block import BlockReader, block_disk_size
from ..ndb.btree import BBTEntry, NBTEntry
from ..ndb.nodedb import NodeRef
from ..ndb.subnode import SubnodeReader
from ..variant import Variant
from .carve import CarveResult


@dataclass
class RebuiltIndex:
    """The reconciled BBT/NBT rebuilt from carved entries (PLAN §7.3)."""

    bbt: Dict[int, BBTEntry] = field(default_factory=dict)
    nbt: Dict[int, NBTEntry] = field(default_factory=dict)
    dangling_bids: set[int] = field(default_factory=set)


def rebuild_index(carved: CarveResult, *,
                  sink: Optional[WarningSink] = None) -> RebuiltIndex:
    """Reconcile carved BBT/NBT entries into deduped indexes (PLAN §7.3).

    BBT entries are deduped by BID; on a collision the one whose carved block
    trailer-validated (present in ``carved.blocks``) wins, else the first seen.
    NBT entries are deduped by NID (first seen wins — a later overlapping carve
    is flagged ``OVERLAP_LOSER`` but both are retained in forensic output via the
    block list).  Dangling node BIDs (referenced but not in the rebuilt BBT) are
    collected for ``DANGLING_BID`` annotation.
    """
    sink = sink if sink is not None else WarningSink()
    idx = RebuiltIndex()

    validated_bids = {b.bid for b in carved.blocks}
    for ent in carved.bbt_entries:
        bid = ent.bid
        if bid in idx.bbt:
            # Prefer a trailer-validated block on collision (§7.3 arbitration).
            if bid in validated_bids and idx.bbt[bid].bid not in validated_bids:
                idx.bbt[bid] = ent
            continue
        idx.bbt[bid] = ent

    for ent in carved.nbt_entries:
        if ent.nid in idx.nbt:
            sink.warn(WarnCode.OVERLAP_LOSER,
                      f"duplicate carved NBTENTRY nid={ent.nid:#x}",
                      where="rebuild")
            continue
        idx.nbt[ent.nid] = ent

    # Dangling data/sub BIDs.
    for ent in idx.nbt.values():
        for bid in (ent.bid_data, ent.bid_sub):
            if bid and bid not in idx.bbt:
                idx.dangling_bids.add(bid)
    if idx.dangling_bids:
        sink.warn(WarnCode.OUT_OF_BOUNDS,
                  f"{len(idx.dangling_bids)} dangling BIDs after rebuild",
                  where="rebuild")
    return idx


class RebuiltNodeDatabase:
    """A :class:`NodeDatabase`-compatible facade over a rebuilt index (§7.6).

    Exposes ``node(nid)``, ``iter_nbt()``, ``iter_bbt()``, ``variant`` and
    ``crypt_method`` so a carved node can be handed to the unchanged
    LTP/messaging parser for cross-validation (PLAN §7.6).  Only the subset the
    parser touches is implemented; this is a recovery facade, not the live DB.
    """

    def __init__(self, reader: FileReader, variant: Variant, *,
                 index: RebuiltIndex, crypt_method: int,
                 sink: Optional[WarningSink] = None) -> None:
        self.reader = reader
        self.variant = variant
        self.sink = sink if sink is not None else WarningSink()
        self.crypt_method = crypt_method
        self._index = index
        self._bbt = index.bbt
        self._nbt = index.nbt
        self._block_reader = BlockReader(
            reader, variant, bbt=self._bbt, sink=self.sink,
            crypt_method=crypt_method)
        self._subnode_reader = SubnodeReader(
            self._block_reader, variant, sink=self.sink)

    def node(self, nid: int) -> Optional[NodeRef]:
        """Return a :class:`NodeRef` for ``nid`` from the rebuilt NBT."""
        ent = self._nbt.get(nid)
        if ent is None:
            return None
        return NodeRef(self, ent.nid, ent.bid_data, ent.bid_sub, ent.nid_parent)

    def iter_nbt(self) -> Iterator[NBTEntry]:
        """Iterate rebuilt NBT entries."""
        return iter(self._nbt.values())

    def iter_bbt(self) -> Iterator[BBTEntry]:
        """Iterate rebuilt BBT entries."""
        return iter(self._bbt.values())

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (f"RebuiltNodeDatabase(nodes={len(self._nbt)}, "
                f"blocks={len(self._bbt)}, variant={self.variant.name})")


# ---------------------------------------------------------------------------
# AMap reconstruction — IN-MEMORY / ADVISORY ONLY (PLAN §7.4, Appendix A N1/H14)
# ---------------------------------------------------------------------------
@dataclass
class AdvisoryAMap:
    """An in-memory allocation bitmap rebuilt from the live/rebuilt BBT (§7.4).

    NEVER written to the evidence file (Appendix A N1).  ``allocated_extents``
    are ``[ib, ib+disk)`` for every block reachable through the (live or
    rebuilt) BBT; ``f_amap_valid_advisory`` is the spec's "valid" sentinel
    (0x02) for the *rebuilt* map, recorded for provenance only.
    """

    granule: int
    file_size: int
    allocated_extents: List[tuple[int, int]]
    f_amap_valid_advisory: int = 0x02


def reconstruct_amap(bbt: Dict[int, BBTEntry], variant: Variant, *,
                     file_size: int) -> AdvisoryAMap:
    """Rebuild an advisory allocation map from a BBT ([MS-PST] §2.6.1.3.7).

    Marks each block's on-disk footprint (``ceil((cb+trailer)/64)*64``)
    allocated.  Purely in-memory: the result feeds free-space computation for
    carving (Appendix A H14) and is **never** written back to the file.
    """
    extents: List[tuple[int, int]] = []
    for ent in bbt.values():
        ib = ent.bref.ib
        disk = block_disk_size(ent.cb, variant)
        if 0 <= ib < file_size:
            extents.append((ib, min(ib + disk, file_size)))
    return AdvisoryAMap(
        granule=variant.block_align,
        file_size=file_size,
        allocated_extents=extents,
    )
