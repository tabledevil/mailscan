"""Format-variant layout constants — the single typed source of NDB geometry.

ALL byte offsets/sizes here are spec-verified against [MS-PST] §2.2.2.6 and
recorded in docs/PST_OST_PARSER_PLAN.md Appendix A. Do not hand-edit a constant
without a locking test (PLAN §0.5: trust nothing without a test vector).

The 4K-OST variant is marked ``verified=False``: its trailer geometry is the
working hypothesis (PLAN Appendix A H20) pending a real Outlook 2013+ OST
fixture, so code paths that depend on it must check ``Variant.verified``.
"""
from __future__ import annotations

from dataclasses import dataclass

MAGIC = b"\x21\x42\x44\x4e"          # "!BDN" at offset 0
MAGIC_CLIENT = b"\x53\x4d"           # "SM" at offset 0x08

# bCryptMethod values ([MS-PST] §2.2.2.6)
CRYPT_NONE = 0x00
CRYPT_PERMUTE = 0x01
CRYPT_CYCLIC = 0x02
CRYPT_EDPCRYPTED = 0x10              # Windows Information Protection — unreadable


@dataclass(frozen=True)
class Variant:
    """Geometry of one PST/OST on-disk format family."""

    name: str
    is_unicode: bool
    # Header field offsets (absolute, from file start)
    root_offset: int
    root_size: int
    crypt_method_offset: int
    # BID/BREF widths
    bid_size: int            # bytes in a BID (and IB)
    bref_size: int           # BID + IB
    # Trailer geometry
    page_size: int
    page_trailer_size: int
    block_trailer_size: int
    # B-tree page entry counts live in the page itself (cEnt/cbEnt); not fixed here.
    block_align: int = 64    # blocks are padded to this multiple
    verified: bool = True    # False => geometry is a working hypothesis (4K-OST)

    @property
    def ib_size(self) -> int:
        return self.bid_size


# ANSI "small" PST (Outlook 97-2002), wVer 14/15.
ANSI = Variant(
    name="ansi",
    is_unicode=False,
    root_offset=0x00A4,
    root_size=40,
    crypt_method_offset=0x01CD,
    bid_size=4,
    bref_size=8,
    page_size=512,
    page_trailer_size=12,
    block_trailer_size=12,
)

# Unicode PST/OST (Outlook 2003+), wVer 23-35.
UNICODE = Variant(
    name="unicode",
    is_unicode=True,
    root_offset=0x00B4,
    root_size=72,
    crypt_method_offset=0x0201,
    bid_size=8,
    bref_size=16,
    page_size=512,
    page_trailer_size=16,
    block_trailer_size=16,
)

# Unicode 4K-page OST (Outlook 2013+ cached mode), wVer 36/37.
# UNVERIFIED geometry — see PLAN Appendix A H20.
UNICODE_4K = Variant(
    name="unicode4k",
    is_unicode=True,
    root_offset=0x00B4,
    root_size=72,
    crypt_method_offset=0x0201,
    bid_size=8,
    bref_size=16,
    page_size=4096,
    page_trailer_size=24,
    block_trailer_size=16,
    verified=False,
)


def classify(wver: int) -> Variant:
    """Map a header ``wVer`` to its layout family ([MS-PST] §2.2.2.6).

    Raises nothing for unknown versions — callers that want brute-force
    structural inference handle the ``UnsupportedStoreError`` path themselves.
    """
    if wver in (14, 15):
        return ANSI
    if wver in (36, 37):
        return UNICODE_4K
    if wver >= 23:
        return UNICODE
    raise ValueError(f"unrecognised wVer={wver}")


def wver_is_wip_capable(wver: int) -> bool:
    """wVer 37 signals an Outlook that supports WIP; data MAY be EDP-encrypted."""
    return wver == 37
