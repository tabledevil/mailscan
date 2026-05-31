"""MAPI property data types ([MS-OXCDATA] §2.11.1) and the property-tag model.

A property *tag* is ``(prop_id << 16) | prop_type``. ``prop_type`` selects how
the value bytes are interpreted. The ``0x1000`` bit marks a multi-value (MV)
variant of a base scalar type.

Spec-faithful: every base scalar's on-disk width is recorded in ``FIXED_SIZES``
so the LTP layer can decide inline-vs-HNID storage (see PLAN §5.3 / Appendix A:
PST PC records hold only 4 inline bytes, so any type wider than 4 is by-HNID).
"""
from __future__ import annotations

from enum import IntEnum

MV_FLAG = 0x1000


class PropType(IntEnum):
    UNSPECIFIED = 0x0000
    NULL = 0x0001
    INTEGER16 = 0x0002      # PtypInteger16  (i2)        2 bytes
    INTEGER32 = 0x0003      # PtypInteger32  (i4)        4 bytes
    FLOATING32 = 0x0004     # PtypFloating32 (r4)        4 bytes
    FLOATING64 = 0x0005     # PtypFloating64 (r8)        8 bytes
    CURRENCY = 0x0006       # PtypCurrency   int64 /1e4  8 bytes
    FLOATINGTIME = 0x0007   # PtypFloatingTime (OLE date)8 bytes
    ERRORCODE = 0x000A      # PtypErrorCode              4 bytes
    BOOLEAN = 0x000B        # PtypBoolean                1 byte (stored 2)
    OBJECT = 0x000D         # PtypObject / embedded      by-HNID/subnode
    INTEGER64 = 0x0014      # PtypInteger64  (i8)        8 bytes
    STRING8 = 0x001E        # PtypString8 (codepage)     variable
    STRING = 0x001F         # PtypString  (UTF-16LE)     variable
    TIME = 0x0040           # PtypTime (FILETIME)        8 bytes
    GUID = 0x0048           # PtypGuid                   16 bytes
    SERVERID = 0x00FB       # PtypServerId               variable
    RESTRICTION = 0x00FD    # PtypRestriction            variable
    RULEACTION = 0x00FE     # PtypRuleAction             variable
    BINARY = 0x0102         # PtypBinary                 variable

    # Multi-value variants (base | 0x1000)
    MV_INTEGER16 = 0x1002
    MV_INTEGER32 = 0x1003
    MV_FLOATING32 = 0x1004
    MV_FLOATING64 = 0x1005
    MV_CURRENCY = 0x1006
    MV_FLOATINGTIME = 0x1007
    MV_INTEGER64 = 0x1014
    MV_STRING8 = 0x101E
    MV_STRING = 0x101F
    MV_TIME = 0x1040
    MV_GUID = 0x1048
    MV_BINARY = 0x1102


# On-disk width of fixed-width base scalars, in bytes. Absent => variable-length.
FIXED_SIZES: dict[int, int] = {
    PropType.INTEGER16: 2,
    PropType.INTEGER32: 4,
    PropType.FLOATING32: 4,
    PropType.FLOATING64: 8,
    PropType.CURRENCY: 8,
    PropType.FLOATINGTIME: 8,
    PropType.ERRORCODE: 4,
    PropType.BOOLEAN: 1,
    PropType.INTEGER64: 8,
    PropType.TIME: 8,
    PropType.GUID: 16,
}

VARIABLE_TYPES = frozenset({
    PropType.STRING8, PropType.STRING, PropType.BINARY,
    PropType.OBJECT, PropType.SERVERID, PropType.RESTRICTION, PropType.RULEACTION,
})


def is_multivalue(prop_type: int) -> bool:
    return bool(prop_type & MV_FLAG)


def base_type(prop_type: int) -> int:
    """Strip the MV flag to get the element type."""
    return prop_type & ~MV_FLAG


def fixed_size(prop_type: int) -> int | None:
    """Return on-disk width for a fixed scalar, else None (variable-length)."""
    return FIXED_SIZES.get(prop_type)


def is_inline_in_pc(prop_type: int) -> bool:
    """True iff this type's value fits in the 4-byte PC inline slot.

    PLAN Appendix A H5: a PST Property-Context BTH record is cbEnt=6
    (type:2 + dwValueHnid:4), so ONLY types <= 4 bytes are stored inline; all
    wider fixed types (8/16 byte) and every variable type are by-HNID.
    """
    sz = FIXED_SIZES.get(prop_type)
    return sz is not None and sz <= 4


def make_tag(prop_id: int, prop_type: int) -> int:
    return ((prop_id & 0xFFFF) << 16) | (prop_type & 0xFFFF)


def split_tag(tag: int) -> tuple[int, int]:
    return (tag >> 16) & 0xFFFF, tag & 0xFFFF


def tag_str(tag: int) -> str:
    pid, ptype = split_tag(tag)
    return f"0x{pid:04X}{ptype:04X}"
