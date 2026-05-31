"""Named-property map for MSG files (PLAN §10.1 / §6.6, Appendix A H17).

The ``__nameid_version1.0`` storage holds the same ``NAMEID`` bit-packing as the
PST ``NID_NAME_TO_ID_MAP`` (0x61), exposed as three streams ([MS-OXMSG] §2.2.3,
[MS-OXPROPS] §1.3.2):

  * ``__substg1.0_00020102`` — GUID stream: array of 16-byte property-set GUIDs.
  * ``__substg1.0_00030102`` — Entry stream: array of 8-byte ``NAMEID`` records.
  * ``__substg1.0_00040102`` — String stream: UTF-16LE counted string names.

Each ``NAMEID`` ([MS-OXMSG] §2.2.3.1.2) is::

    dwPropertyID/dwStringOffset : u32   (LID, or byte offset into String stream)
    flags                       : u16   (bit 0 = N: 1 => named string, 0 => LID)
    wGuid                       : u15    (0 none, 1 PS_MAPI, 2 PS_PUBLIC_STRINGS,
                                          >=3 => GuidStream[(wGuid-3)])

The resolved named-property index (NPID) is ``0x8000 + ordinal`` where *ordinal*
is the record's 0-based position in the Entry stream ([MS-OXMSG] §2.2.3.1.2;
Appendix A H17).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from ..catalog import namedprops
from ..exceptions import WarnCode, WarningSink

# GUID-set hardcodes from Appendix A H17 (NOT stored in the GUID stream).
PS_MAPI = "00020328-0000-0000-c000-000000000046"
PS_PUBLIC_STRINGS = "00020329-0000-0000-c000-000000000046"

_GUID_STREAM = "__substg1.0_00020102"
_ENTRY_STREAM = "__substg1.0_00030102"
_STRING_STREAM = "__substg1.0_00040102"

_NAMEID_SIZE = 8  # [MS-OXMSG] §2.2.3.1.2 — each NAMEID entry is 8 bytes.


@dataclass
class NamedProp:
    """A resolved named property ([MS-OXMSG] §2.2.3.1.2).

    Attributes:
        npid: The named-property id (``0x8000 + ordinal``).
        guid: Canonical lowercase property-set GUID string.
        lid: The numeric LID, if this is an id-named property (``N == 0``).
        name: The Unicode string name, if this is a string-named property.
    """

    npid: int
    guid: str
    lid: Optional[int] = None
    name: Optional[str] = None

    @property
    def is_string(self) -> bool:
        """Whether this is a string-named (``N == 1``) property."""
        return self.name is not None


class NamedPropMap:
    """Resolve NPIDs (``0x8000+``) to ``(GUID, lid|name)`` for an MSG.

    Built from the three ``__nameid_version1.0`` streams.  A missing/corrupt map
    is non-fatal: :meth:`resolve` returns ``None`` and the caller falls back to a
    numeric ``0x8xxx`` display with the ``NAMEID_MISSING`` flag (AC-5).
    """

    def __init__(self, *, sink: Optional[WarningSink] = None) -> None:
        self.sink = sink if sink is not None else WarningSink()
        self._by_npid: dict[int, NamedProp] = {}

    @classmethod
    def from_streams(
        cls,
        guid_stream: Optional[bytes],
        entry_stream: Optional[bytes],
        string_stream: Optional[bytes],
        *,
        sink: Optional[WarningSink] = None,
    ) -> "NamedPropMap":
        """Build a map from the three raw ``__nameid_version1.0`` streams.

        Args:
            guid_stream: ``__substg1.0_00020102`` bytes, or ``None``.
            entry_stream: ``__substg1.0_00030102`` bytes, or ``None``.
            string_stream: ``__substg1.0_00040102`` bytes, or ``None``.
            sink: Optional warning sink.

        Returns:
            A populated :class:`NamedPropMap` (possibly empty on missing input).
        """
        self = cls(sink=sink)
        if not entry_stream:
            self.sink.warn(WarnCode.NAMEID_MISSING, "no entry stream", where="__nameid")
            return self

        guids = self._parse_guid_stream(guid_stream or b"")
        n = len(entry_stream) // _NAMEID_SIZE
        for ordinal in range(n):
            off = ordinal * _NAMEID_SIZE
            id_or_off, flags, wguid = struct.unpack_from("<IHH", entry_stream, off)
            is_string = bool(flags & 0x0001)
            guid_idx = wguid >> 1  # wGuid occupies the high 15 bits (bit0 == N)
            guid = self._resolve_guid(guid_idx, guids)
            npid = 0x8000 + ordinal
            if is_string:
                name = self._read_string(string_stream or b"", id_or_off)
                self._by_npid[npid] = NamedProp(npid=npid, guid=guid, name=name)
            else:
                self._by_npid[npid] = NamedProp(npid=npid, guid=guid, lid=id_or_off)
        return self

    @staticmethod
    def _parse_guid_stream(raw: bytes) -> list[str]:
        """Split the GUID stream into canonical GUID strings ([MS-OXMSG] §2.2.3.1.1)."""
        out: list[str] = []
        for i in range(0, len(raw) - 15, 16):
            out.append(namedprops.guid_bytes_to_str(raw[i : i + 16]))
        return out

    def _resolve_guid(self, guid_idx: int, guids: list[str]) -> str:
        """Map a ``wGuid`` index to a GUID string (Appendix A H17).

        ``0`` => none (PS_MAPI sentinel), ``1`` => PS_MAPI, ``2`` =>
        PS_PUBLIC_STRINGS, ``>=3`` => ``GuidStream[guid_idx - 3]``.
        """
        if guid_idx <= 1:
            return PS_MAPI
        if guid_idx == 2:
            return PS_PUBLIC_STRINGS
        sidx = guid_idx - 3
        if 0 <= sidx < len(guids):
            return guids[sidx]
        self.sink.warn(
            WarnCode.NAMEID_MISSING,
            f"wGuid index {guid_idx} out of range ({len(guids)} guids)",
            where="__nameid",
        )
        return PS_MAPI

    @staticmethod
    def _read_string(raw: bytes, offset: int) -> Optional[str]:
        """Read a counted UTF-16LE string at ``offset`` in the String stream.

        Layout ([MS-OXMSG] §2.2.3.1.3): u32 byte-length, then that many bytes of
        UTF-16LE text.
        """
        if offset + 4 > len(raw):
            return None
        (cb,) = struct.unpack_from("<I", raw, offset)
        start = offset + 4
        chunk = raw[start : start + cb]
        try:
            return chunk.decode("utf-16-le")
        except Exception:
            return chunk.decode("utf-16-le", "replace")

    # -- lookups -----------------------------------------------------------

    def resolve(self, npid: int) -> Optional[NamedProp]:
        """Resolve an NPID (``0x8000+``) to its :class:`NamedProp`, or ``None``."""
        return self._by_npid.get(npid)

    def label(self, npid: int) -> Optional[str]:
        """Human label for an NPID via :mod:`pstforensic.catalog`, else ``None``.

        For id-named props the catalog's :func:`namedprops.lid_name` provides a
        friendly ``PidLid*`` label; string-named props return their name.
        """
        np = self.resolve(npid)
        if np is None:
            return None
        if np.is_string:
            return np.name
        label = namedprops.lid_name(np.guid, np.lid) if np.lid is not None else None
        if label:
            return label
        set_label = namedprops.set_name(np.guid) or np.guid
        return f"{set_label}:0x{np.lid:04X}" if np.lid is not None else set_label

    def __len__(self) -> int:
        return len(self._by_npid)
