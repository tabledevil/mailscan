"""BID / NID / BREF parsing and normalization ([MS-PST] §2.2.2.1-§2.2.2.2).

A **BID** (Block ID, [MS-PST] §2.2.2.2) and a **NID** (Node ID, §2.2.2.1) are
the two identifier spaces of the NDB layer.  A **BREF** (§2.2.2.4) pairs a BID
with an IB (byte offset).

Reserved-bit normalization (Appendix A H22 / [MS-PST] §2.2.2.2):
  * A *block* BID's two low bits are flags:
      - bit ``A`` / ``r`` (value ``0x1``) is *reserved* and MUST be cleared
        before using the BID as a BBT lookup key.
      - bit ``B`` / ``i`` (value ``0x2``) is the *internal* flag: set ⇒ the
        block is an internal/metadata block (XBLOCK/XXBLOCK/SLBLOCK/SIBLOCK),
        clear ⇒ a data block.
  * A *page* BID is allocated from a separate counter and does not carry the
    ``i`` meaning; the BBT/NBT page BREFs in the header point at pages, while
    the per-node ``bidData``/``bidSub`` point at blocks (Appendix A H22).

ANSI uses 4-byte BIDs; Unicode/4K use 8-byte BIDs.  The flag bits live in the
low byte in both, so the normalization arithmetic is width-independent.
"""
from __future__ import annotations

from dataclasses import dataclass

# BID flag bits ([MS-PST] §2.2.2.2).
BID_RESERVED_BIT = 0x1   # 'A'/'r' — reserved, clear before BBT lookup
BID_INTERNAL_BIT = 0x2   # 'B'/'i' — set => internal (XBLOCK/SLBLOCK/...)

# NID type field is the low 5 bits ([MS-PST] §2.2.2.1).
NID_TYPE_BITS = 5
NID_TYPE_MASK = (1 << NID_TYPE_BITS) - 1  # 0x1F

# Well-known nidType values ([MS-PST] §2.2.2.1).
NID_TYPE_HID = 0x00
NID_TYPE_INTERNAL = 0x01
NID_TYPE_NORMAL_FOLDER = 0x02
NID_TYPE_SEARCH_FOLDER = 0x03
NID_TYPE_NORMAL_MESSAGE = 0x04
NID_TYPE_ATTACHMENT = 0x05
NID_TYPE_SEARCH_UPDATE_QUEUE = 0x06
NID_TYPE_SEARCH_CRITERIA_OBJECT = 0x07
NID_TYPE_ASSOC_MESSAGE = 0x08
NID_TYPE_CONTENTS_TABLE_INDEX = 0x0A
NID_TYPE_RECEIVE_FOLDER_TABLE = 0x0B
NID_TYPE_OUTGOING_QUEUE_TABLE = 0x0C
NID_TYPE_HIERARCHY_TABLE = 0x0D
NID_TYPE_CONTENTS_TABLE = 0x0E
NID_TYPE_ASSOC_CONTENTS_TABLE = 0x0F
NID_TYPE_SEARCH_CONTENTS_TABLE = 0x10
NID_TYPE_ATTACHMENT_TABLE = 0x11
NID_TYPE_RECIPIENT_TABLE = 0x12
NID_TYPE_SEARCH_TABLE_INDEX = 0x13
NID_TYPE_LTP = 0x1F

# Well-known special NIDs referenced across the NDB/messaging layers.
NID_MESSAGE_STORE = 0x21
NID_NAME_TO_ID_MAP = 0x61
NID_ROOT_FOLDER = 0x122


def nid_type(nid: int) -> int:
    """Return the 5-bit ``nidType`` of a NID ([MS-PST] §2.2.2.1)."""
    return nid & NID_TYPE_MASK


def nid_index(nid: int) -> int:
    """Return the ``nidIndex`` (the bits above the 5-bit type)."""
    return (nid >> NID_TYPE_BITS) & 0x7FFFFFFF


def make_nid(nid_type_: int, nid_index_: int) -> int:
    """Compose a NID from its type and index ([MS-PST] §2.2.2.1)."""
    return ((nid_index_ & 0x7FFFFFFF) << NID_TYPE_BITS) | (nid_type_ & NID_TYPE_MASK)


def normalize_bid(bid: int) -> int:
    """Clear the reserved bit ``A``/``r`` to get the canonical BBT lookup key.

    Per [MS-PST] §2.2.2.2 and Appendix A H22, the low ``0x1`` bit is reserved
    and must be masked off before comparing/looking up a block BID; the
    internal ``0x2`` bit is *retained* because BBT keys keep it.
    """
    return bid & ~BID_RESERVED_BIT


def bid_is_internal(bid: int) -> bool:
    """True iff the BID's internal flag (``0x2``) is set ([MS-PST] §2.2.2.2)."""
    return bool(bid & BID_INTERNAL_BIT)


@dataclass(frozen=True)
class BREF:
    """A Block Reference: a (normalized) BID plus its file offset IB.

    ``bid`` is stored already normalized (reserved bit cleared) so it is a
    valid BBT key; ``raw_bid`` preserves the on-disk value including flags.
    """

    bid: int          # normalized (reserved bit cleared)
    ib: int           # absolute byte offset into the file
    raw_bid: int      # on-disk BID with all flag bits intact

    @property
    def internal(self) -> bool:
        """True iff the source BID had the internal flag set."""
        return bid_is_internal(self.raw_bid)


def parse_bref(buf: bytes, off: int, bid_size: int) -> BREF:
    """Parse a BREF (BID then IB) at ``off`` in ``buf`` ([MS-PST] §2.2.2.4).

    ``bid_size`` is 4 (ANSI) or 8 (Unicode/4K); the IB has the same width.
    Returns a :class:`BREF` with the BID normalized for BBT lookup.
    """
    raw_bid = int.from_bytes(buf[off:off + bid_size], "little")
    ib = int.from_bytes(buf[off + bid_size:off + 2 * bid_size], "little")
    return BREF(bid=normalize_bid(raw_bid), ib=ib, raw_bid=raw_bid)
