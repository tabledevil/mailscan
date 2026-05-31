"""Exception and warning hierarchy for pstforensic.

Design principle (see docs/PST_OST_PARSER_PLAN.md §0.5, §4): parsing is
*recovery-first*. Structural defects produce a ``ParseWarning`` recorded on the
object being parsed and parsing continues; only conditions that make further
reading impossible (not a PST, WIP-encrypted) raise.
"""
from __future__ import annotations

from dataclasses import dataclass, field


class PstForensicError(Exception):
    """Base class for all hard errors raised by pstforensic."""


class NotAPstError(PstForensicError):
    """The bytes are not a recognisable PST/OST store (no ``!BDN`` magic)."""


class NotAMsgError(PstForensicError):
    """The bytes are not a recognisable MSG (OLE/CFBF) message."""


class EncryptedStoreError(PstForensicError):
    """Store is WIP/EDP-encrypted (``bCryptMethod == 0x10``); content unreadable.

    Clear metadata may still be extractable in a dedicated mode; callers that
    want that should pass ``allow_encrypted_metadata=True`` where supported.
    """


class UnsupportedStoreError(PstForensicError):
    """Recognised as a store but no known/guessable layout fits it."""


# --- Warning codes ---------------------------------------------------------
# Stable string codes attached to ParseWarning.code and to object.flags sets.
class WarnCode:
    SIG_MISMATCH = "SIG_MISMATCH"
    HEADER_CRC_FAIL = "HEADER_CRC_FAIL"
    PAGE_CRC_FAIL = "PAGE_CRC_FAIL"
    BLOCK_CRC_FAIL = "BLOCK_CRC_FAIL"
    AMAP_INVALID = "AMAP_INVALID"
    ENTRY_OVERFLOW = "ENTRY_OVERFLOW"
    CYCLE_DETECTED = "CYCLE_DETECTED"
    ENCODE_GUESSED = "ENCODE_GUESSED"
    COMPRESS_FAIL = "COMPRESS_FAIL"
    NAMEID_MISSING = "NAMEID_MISSING"
    RTF_CRC_FAIL = "RTF_CRC_FAIL"
    TRUNCATED = "TRUNCATED"
    OVERLAP_LOSER = "OVERLAP_LOSER"
    OUT_OF_BOUNDS = "OUT_OF_BOUNDS"
    UNVERIFIED_CONST = "UNVERIFIED_CONST"


@dataclass
class ParseWarning:
    """A non-fatal anomaly encountered while parsing.

    Collected rather than raised so a single defect never aborts a whole store.
    """

    code: str
    detail: str = ""
    where: str = ""  # e.g. "nid=0x21", "bid=0x4a0", file offset

    def __str__(self) -> str:  # pragma: no cover - trivial
        loc = f" @ {self.where}" if self.where else ""
        return f"[{self.code}]{loc} {self.detail}".rstrip()


@dataclass
class WarningSink:
    """Accumulates warnings during a parse; shared down the call tree."""

    warnings: list[ParseWarning] = field(default_factory=list)

    def warn(self, code: str, detail: str = "", where: str = "") -> ParseWarning:
        w = ParseWarning(code=code, detail=detail, where=where)
        self.warnings.append(w)
        return w

    def codes(self) -> set[str]:
        return {w.code for w in self.warnings}

    def __len__(self) -> int:  # pragma: no cover - trivial
        return len(self.warnings)
