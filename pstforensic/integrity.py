"""Per-object integrity findings (PLAN §14.3 / §14.4).

Reading is tolerant (what Kernel PST Viewer accepts, we read); *verdicts* are
strict and recorded on the object they concern instead of gating the read.

  * :class:`PageVerdict` / :class:`BlockVerdict` — what every page/block read
    established (CRC, signature, trailer BID/cb, geometry).
  * :class:`Finding` — one stable-coded anomaly with its location.
  * :class:`Integrity` — the findings attached to a node, message, folder or
    store, plus the interpretation level of the object as a whole.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

# Interpretation levels, strongest first (PLAN §14.4).
VERIFIED = "verified"      # independent check a wrong choice would fail
CONSISTENT = "consistent"  # structure fits, no checksum to prove it
INFERRED = "inferred"      # inherited from a verified parent
GUESSED = "guessed"        # heuristic only
RAW_ONLY = "raw_only"      # nothing fits; raw bytes preserved

LEVELS = (VERIFIED, CONSISTENT, INFERRED, GUESSED, RAW_ONLY)


def weakest(levels: Iterable[str]) -> str:
    """Return the weakest level of ``levels`` (``VERIFIED`` if empty)."""
    worst = 0
    for lv in levels:
        worst = max(worst, LEVELS.index(lv))
    return LEVELS[worst]


# Finding codes (stable strings; superset of the sink's WarnCode values).
HEADER_MAGIC_BAD = "HEADER_MAGIC_BAD"
HEADER_UNUSABLE = "HEADER_UNUSABLE"
HEADER_CRC_FAIL = "HEADER_CRC_FAIL"
HEADER_CLIENT_MAGIC_BAD = "HEADER_CLIENT_MAGIC_BAD"
VARIANT_FROM_EVIDENCE = "VARIANT_FROM_EVIDENCE"
WVER_UNUSUAL = "WVER_UNUSUAL"
VARIANT_GUESSED = "VARIANT_GUESSED"
EOF_MISMATCH = "EOF_MISMATCH"
AMAP_INVALID = "AMAP_INVALID"
PAGE_CRC_FAIL = "PAGE_CRC_FAIL"
PAGE_SIG_FAIL = "PAGE_SIG_FAIL"
PAGE_BID_MISMATCH = "PAGE_BID_MISMATCH"
PAGE_TYPE_BAD = "PAGE_TYPE_BAD"
PAGE_GEOMETRY_BAD = "PAGE_GEOMETRY_BAD"
PAGE_UNREADABLE = "PAGE_UNREADABLE"
BLOCK_CRC_FAIL = "BLOCK_CRC_FAIL"
BLOCK_SIG_FAIL = "BLOCK_SIG_FAIL"
BLOCK_BID_MISMATCH = "BLOCK_BID_MISMATCH"
BLOCK_CB_MISMATCH = "BLOCK_CB_MISMATCH"
BLOCK_TRUNCATED = "BLOCK_TRUNCATED"
BLOCK_MISSING = "BLOCK_MISSING"
BLOCK_FROM_SCAN = "BLOCK_FROM_SCAN"
NODE_FROM_SCAN = "NODE_FROM_SCAN"
CRYPT_FROM_EVIDENCE = "CRYPT_FROM_EVIDENCE"
CRYPT_GUESSED = "CRYPT_GUESSED"
CRYPT_METHOD_UNKNOWN = "CRYPT_METHOD_UNKNOWN"
SUBNODES_UNKNOWN = "SUBNODES_UNKNOWN"
RECOVERED_ALT_COPY = "RECOVERED_ALT_COPY"


@dataclass(frozen=True, slots=True)
class Finding:
    """One anomaly, located by file offset / BID / NID where known."""

    code: str
    detail: str = ""
    ib: Optional[int] = None
    bid: Optional[int] = None
    nid: Optional[int] = None

    def __str__(self) -> str:  # pragma: no cover - trivial
        loc = []
        if self.nid is not None:
            loc.append(f"nid={self.nid:#x}")
        if self.bid is not None:
            loc.append(f"bid={self.bid:#x}")
        if self.ib is not None:
            loc.append(f"ib={self.ib:#x}")
        where = f" @ {' '.join(loc)}" if loc else ""
        return f"[{self.code}]{where} {self.detail}".rstrip()


@dataclass
class Integrity:
    """Findings attached to one object, deduplicated, order-preserving."""

    findings: list[Finding] = field(default_factory=list)
    level: str = VERIFIED

    def add(self, code: str, detail: str = "", *, ib: Optional[int] = None,
            bid: Optional[int] = None, nid: Optional[int] = None) -> Finding:
        f = Finding(code, detail, ib=ib, bid=bid, nid=nid)
        if f not in self.findings:
            self.findings.append(f)
        return f

    def extend(self, findings: Iterable[Finding]) -> None:
        for f in findings:
            if f not in self.findings:
                self.findings.append(f)

    def merge(self, other: "Integrity") -> None:
        self.extend(other.findings)
        self.level = weakest((self.level, other.level))

    @property
    def codes(self) -> set[str]:
        return {f.code for f in self.findings}

    @property
    def ok(self) -> bool:
        return not self.findings

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.findings)


@dataclass(frozen=True, slots=True)
class PageVerdict:
    """What reading one B-tree page established ([MS-PST] §2.2.2.7.1)."""

    ib: int
    ptype: int
    ptype_ok: bool       # ptype == ptypeRepeat == expected
    geometry_ok: bool    # cEntMax/cbEnt match the variant's constants
    crc_ok: bool
    sig_ok: bool
    bid_ok: bool         # trailer bid == BREF bid (None-equivalent: True if unknown)

    def findings(self) -> list[Finding]:
        out = []
        if not self.ptype_ok:
            out.append(Finding(PAGE_TYPE_BAD, f"ptype {self.ptype:#x}", ib=self.ib))
        if not self.geometry_ok:
            out.append(Finding(PAGE_GEOMETRY_BAD, "cEntMax/cbEnt implausible", ib=self.ib))
        if not self.crc_ok:
            out.append(Finding(PAGE_CRC_FAIL, ib=self.ib))
        if not self.sig_ok:
            out.append(Finding(PAGE_SIG_FAIL, ib=self.ib))
        if not self.bid_ok:
            out.append(Finding(PAGE_BID_MISMATCH, ib=self.ib))
        return out


@dataclass(frozen=True, slots=True)
class BlockVerdict:
    """What reading one block established ([MS-PST] §2.2.2.8.1)."""

    bid: int
    ib: Optional[int]
    crc_ok: bool = True
    sig_ok: bool = True
    bid_ok: bool = True
    cb_ok: bool = True
    complete: bool = True
    from_scan: bool = False   # located via the full-file scan, not the BBT
    missing: bool = False     # not locatable at all

    def findings(self) -> list[Finding]:
        if self.missing:
            return [Finding(BLOCK_MISSING, bid=self.bid)]
        out = []
        if self.from_scan:
            out.append(Finding(BLOCK_FROM_SCAN, bid=self.bid, ib=self.ib))
        if not self.complete:
            out.append(Finding(BLOCK_TRUNCATED, bid=self.bid, ib=self.ib))
        if not self.cb_ok:
            out.append(Finding(BLOCK_CB_MISMATCH, bid=self.bid, ib=self.ib))
        if not self.bid_ok:
            out.append(Finding(BLOCK_BID_MISMATCH, bid=self.bid, ib=self.ib))
        if not self.crc_ok:
            out.append(Finding(BLOCK_CRC_FAIL, bid=self.bid, ib=self.ib))
        if not self.sig_ok:
            out.append(Finding(BLOCK_SIG_FAIL, bid=self.bid, ib=self.ib))
        return out

    @property
    def verified(self) -> bool:
        return (not self.missing and self.crc_ok and self.sig_ok
                and self.bid_ok and self.cb_ok and self.complete)
