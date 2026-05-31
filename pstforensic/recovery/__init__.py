"""pstforensic.recovery — deleted/orphan item recovery + confidence scoring.

Public surface (CONTRACTS §"recovery"):

  * :class:`~pstforensic.recovery.engine.RecoveryEngine` — the FULL cascade
    (trusted walk → signature carve → BBT/NBT rebuild → encode brute force →
    deleted/orphan/slack engine, merged through dedup) that surfaces
    deleted/orphaned items as :class:`~pstforensic.recovery.engine.RecoveredItem`.
  * Scoring + free-space algebra in :mod:`pstforensic.recovery.score`.
  * Cascade stage modules: :mod:`~pstforensic.recovery.carve`,
    :mod:`~pstforensic.recovery.rebuild`, :mod:`~pstforensic.recovery.encode_detect`,
    :mod:`~pstforensic.recovery.orphan`, :mod:`~pstforensic.recovery.dedup`.
"""
from __future__ import annotations

from .carve import CarveResult, CarvedBlock, carve
from .dedup import dedup, dedup_key, envelope_key
from .encode_detect import EncodeGuess, detect_encode_method
from .engine import RecoveredItem, RecoveryEngine
from .orphan import (
    HardDeletedCandidate,
    OrphanPC,
    OrphanScan,
    SlackFragment,
    SoftDeletedFolder,
    carve_hard_deleted,
    classify_soft_deleted_folders,
    extract_slack_fragments,
    find_orphan_pcs,
    free_space_for_carving,
)
from .rebuild import (
    AdvisoryAMap,
    RebuiltIndex,
    RebuiltNodeDatabase,
    rebuild_index,
    reconstruct_amap,
)
from .score import (
    FreeSpace,
    RecoveryMeta,
    Signals,
    compute_free_space,
    score_confidence,
)

__all__ = [
    # engine + result
    "RecoveryEngine",
    "RecoveredItem",
    # scoring / free space
    "RecoveryMeta",
    "Signals",
    "FreeSpace",
    "score_confidence",
    "compute_free_space",
    # carve
    "carve",
    "CarveResult",
    "CarvedBlock",
    # rebuild
    "rebuild_index",
    "reconstruct_amap",
    "RebuiltIndex",
    "RebuiltNodeDatabase",
    "AdvisoryAMap",
    # encode detect
    "detect_encode_method",
    "EncodeGuess",
    # orphan / deleted / slack
    "classify_soft_deleted_folders",
    "carve_hard_deleted",
    "find_orphan_pcs",
    "extract_slack_fragments",
    "free_space_for_carving",
    "SoftDeletedFolder",
    "HardDeletedCandidate",
    "OrphanPC",
    "SlackFragment",
    "OrphanScan",
    # dedup
    "dedup",
    "dedup_key",
    "envelope_key",
]
