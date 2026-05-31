"""Recovery provenance + confidence scoring (PLAN §7.7 / §8.5, Appendix A H14/H15).

This module is deliberately *honest* about uncertainty (Appendix A H15): nothing
here claims "100% recovery".  Every recovered item carries a :class:`RecoveryMeta`
whose ``confidence`` is a weighted, documented sum of structural signals, mapped
to the bands declared in PLAN §7.7.

It also exposes the **three free-space sets kept separate** (Appendix A H14):

  * ``on_disk_free``       — region the on-disk ROOT/AMap *claims* is free.
  * ``rebuilt_reachable``  — region covered by the rebuilt **live** BBT
    (every ``[ib, ib+disk)`` of a reachable block).
  * ``disagreement``       — the XOR / set-symmetric-difference of the two
    (a low-confidence *secondary* signal, NEVER the carving source).

The carving free-space (the region to scan for hard-deleted blocks) is
``free_for_carving = full_file_span - rebuilt_reachable`` — i.e. **NOT covered
by the rebuilt live BBT**, NOT the AMap XOR (codex+gemini both flagged XOR as
unsound; PLAN §7.4/§8.2 and Appendix A H14).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal, Optional

# Recovery method tags ([PLAN] §8.5).
Method = Literal["btree", "dumpster", "carve_hard", "orphan_pc", "slack"]

# Hard-deleted recovery classes ([PLAN] §8.2, Appendix A H15 — these describe
# *how much* survived, never imply a full reconstruction).
RecoveryClass = Literal[
    "pc_plus_subnode",               # top-level NBT entry survived; subnodes live
    "pc_body_only",                  # no bidSub → envelope/body only
    "attachment_or_recipient_orphan",
    "partial_fragment",
]

# ---------------------------------------------------------------------------
# Confidence weights (PLAN §7.7) — declared HEURISTIC and tunable on a labelled
# set (Appendix A H15).  They sum to 1.0 so a fully-clean tree item scores 1.0.
# ---------------------------------------------------------------------------
W_TREE_REACHED = 0.40       # reached by the trusted B-tree walk (Stage 0)
W_BLOCK_CRC = 0.15          # block CRC valid (§4.6)
W_PAGE_SIG = 0.10           # page/trailer signature valid (§4.2)
W_PARENT_RESOLVES = 0.10    # parent NID resolves, acyclic (§7.3)
W_LTP_PARSE = 0.15          # LTP → valid PC + IPM.* class (§7.6)
W_CREF_OK = 0.05            # cRef consistent / no overlap loss (§7.3)
W_NOT_SLACK = 0.05          # not in slack/free per rebuilt AMap (§7.4)

# Confidence bands (PLAN §7.7).
BAND_TREE_CLEAN = 1.0
BAND_SOFT_DELETED = 0.95
BAND_HARD_MAX = 0.85
BAND_HARD_MIN = 0.70
BAND_ORPHAN_MAX = 0.80
BAND_ORPHAN_MIN = 0.60
BAND_SLACK_MAX = 0.70
BAND_SLACK_MIN = 0.50


@dataclass
class RecoveryMeta:
    """Provenance + confidence attached to one recovered item (PLAN §8.5).

    Attributes:
        method: How the item was recovered (``btree``/``dumpster``/
            ``carve_hard``/``orphan_pc``/``slack``).
        confidence: 0..1 weighted-signal confidence (PLAN §7.7).
        deleted_on: Resolved deletion timestamp, or ``None`` (H9 provenance via
            the catalog at runtime — never a hardcoded id).
        deleted_on_source: The ``PidTag*`` name that supplied ``deleted_on``
            (provenance record — Appendix A H9), or ``None``.
        attributed_folder: Resolved folder path, ``"LostAndFound"``, or ``None``.
        attribution_confidence: 0..1 confidence in ``attributed_folder``.
        recovery_class: How much of the item survived (PLAN §8.2), or ``None``.
        truncated: True iff the item is known-incomplete.
        flags: Warning-code strings observed for this item.
        duplicate_count: Number of duplicate carves collapsed into this one.
    """

    method: Method
    confidence: float
    deleted_on: Optional[datetime] = None
    deleted_on_source: Optional[str] = None
    attributed_folder: Optional[str] = None
    attribution_confidence: float = 0.0
    recovery_class: Optional[RecoveryClass] = None
    truncated: bool = False
    flags: set[str] = field(default_factory=set)
    duplicate_count: int = 1
    raw_pc: Optional[bytes] = None  # raw carved PC bytes (dedup fallback, §8.6)


@dataclass
class Signals:
    """The structural signals feeding :func:`score_confidence` (PLAN §7.7)."""

    tree_reached: bool = False
    block_crc_ok: bool = False
    page_sig_ok: bool = False
    parent_resolves: bool = False
    ltp_pc_ok: bool = False
    cref_ok: bool = False
    not_slack: bool = False


def score_confidence(sig: Signals) -> float:
    """Weighted-sum confidence from structural signals (PLAN §7.7).

    The weights are the declared-heuristic constants ``W_*`` (Appendix A H15);
    the result is clamped to ``[0.0, 1.0]``.
    """
    total = (
        (W_TREE_REACHED if sig.tree_reached else 0.0)
        + (W_BLOCK_CRC if sig.block_crc_ok else 0.0)
        + (W_PAGE_SIG if sig.page_sig_ok else 0.0)
        + (W_PARENT_RESOLVES if sig.parent_resolves else 0.0)
        + (W_LTP_PARSE if sig.ltp_pc_ok else 0.0)
        + (W_CREF_OK if sig.cref_ok else 0.0)
        + (W_NOT_SLACK if sig.not_slack else 0.0)
    )
    return max(0.0, min(1.0, total))


# ---------------------------------------------------------------------------
# Free-space set algebra (Appendix A H14) — the THREE sets kept separate.
# ---------------------------------------------------------------------------
# An "extent" is a half-open byte range ``(start, end)``.
Extent = tuple[int, int]


def _normalize(extents: list[Extent]) -> list[Extent]:
    """Merge overlapping/adjacent extents into a sorted, disjoint list."""
    spans = sorted((s, e) for s, e in extents if e > s)
    out: list[Extent] = []
    for s, e in spans:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _complement(covered: list[Extent], file_size: int) -> list[Extent]:
    """Return ``[0, file_size)`` minus the (normalized) ``covered`` extents."""
    covered = _normalize(covered)
    out: list[Extent] = []
    cursor = 0
    for s, e in covered:
        if s > cursor:
            out.append((cursor, min(s, file_size)))
        cursor = max(cursor, e)
        if cursor >= file_size:
            break
    if cursor < file_size:
        out.append((cursor, file_size))
    return out


def _symmetric_difference(a: list[Extent], b: list[Extent]) -> list[Extent]:
    """Byte-wise symmetric difference (XOR) of two extent sets."""
    a = _normalize(a)
    b = _normalize(b)
    # Build a sweep of boundaries; a byte is in the result iff it is in exactly
    # one of the two sets.
    pts = sorted({p for s, e in a + b for p in (s, e)})
    out: list[Extent] = []
    for i in range(len(pts) - 1):
        lo, hi = pts[i], pts[i + 1]
        mid = lo  # any point in [lo, hi)
        in_a = any(s <= mid < e for s, e in a)
        in_b = any(s <= mid < e for s, e in b)
        if in_a != in_b:
            out.append((lo, hi))
    return _normalize(out)


@dataclass
class FreeSpace:
    """The three separately-reported free-space sets (Appendix A H14).

    Attributes:
        file_size: Total bytes considered (the effective EOF).
        on_disk_free: What the on-disk ROOT/AMap claims is free.
        rebuilt_reachable: Region covered by the rebuilt **live** BBT.
        disagreement: ``on_disk_free`` XOR ``free_for_carving`` (secondary,
            lower-confidence — NEVER used as the carving source).
        free_for_carving: ``[0, file_size)`` minus ``rebuilt_reachable`` — the
            robust signal carving actually scans (H14).
    """

    file_size: int
    on_disk_free: list[Extent]
    rebuilt_reachable: list[Extent]
    disagreement: list[Extent]
    free_for_carving: list[Extent]


def compute_free_space(*, file_size: int,
                       reachable_extents: list[Extent],
                       on_disk_free: Optional[list[Extent]] = None) -> FreeSpace:
    """Compute the three free-space sets, keeping them separate (Appendix A H14).

    Args:
        file_size: Effective end-of-file (carving never scans past it).
        reachable_extents: ``[ib, ib+disk)`` for every block reachable through
            the rebuilt live BBT.
        on_disk_free: Optional region the on-disk AMap/ROOT claims free; when
            omitted the disagreement set is computed against an empty claim.

    Returns:
        A :class:`FreeSpace`.  ``free_for_carving`` is the **primary** signal
        (complement of the reachable set); ``disagreement`` is advisory only.
    """
    reachable = _normalize(reachable_extents)
    free_for_carving = _complement(reachable, file_size)
    on_disk = _normalize(on_disk_free or [])
    disagreement = _symmetric_difference(on_disk, free_for_carving)
    return FreeSpace(
        file_size=file_size,
        on_disk_free=on_disk,
        rebuilt_reachable=reachable,
        disagreement=disagreement,
        free_for_carving=free_for_carving,
    )
