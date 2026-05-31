"""PST named-property map — ``NID_NAME_TO_ID_MAP`` (0x61) resolver (PLAN §6.6).

The store's name-to-id map is a **Property Context** (NID 0x61) carrying three
binary properties (the same three streams the MSG ``__nameid_version1.0`` storage
exposes, but as PC props here — [MS-PST] §2.4.7, [MS-OXPROPS] §1.3.2):

  * ``PidTagNameidStreamGuid``   (0x00020102) — array of 16-byte property-set GUIDs.
  * ``PidTagNameidStreamEntry``  (0x00030102) — array of 8-byte ``NAMEID`` records.
  * ``PidTagNameidStreamString`` (0x00040102) — counted UTF-16LE string names.

Each ``NAMEID`` is 8 bytes ([MS-PST] §2.4.7.1)::

    dwPropertyID / dwStringOffset : u32   (LID, or byte offset into String stream)
    (wGuid << 1) | N              : u16    (bit 0 = N: 1 => named string, 0 => LID;
                                            bits 1-15 = wGuid index)
    wPropIdx                      : u16    (the named-prop ordinal)

The resolved named-property id (NPID) is ``0x8000 + wPropIdx`` ([MS-PST] §2.4.7.1;
Appendix A H17).  ``wGuid`` is resolved with the H17 hardcodes: ``0`` => none,
``1`` => PS_MAPI, ``2`` => PS_PUBLIC_STRINGS (both *NOT* in the GUID stream),
``>= 3`` => ``GuidStream[wGuid - 3]``.

A missing/corrupt map is non-fatal: :meth:`resolve` returns ``None`` and the
caller falls back to a numeric ``0x8xxx`` display with the ``NAMEID_MISSING``
flag (AC-5).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Optional

from ..catalog import namedprops
from ..exceptions import WarnCode, WarningSink
from ..mapi import MapiObject
from ..proptypes import make_tag, PropType

# GUID-set hardcodes from Appendix A H17 (NOT stored in the GUID stream).
PS_MAPI = namedprops.PS_MAPI
PS_PUBLIC_STRINGS = namedprops.PS_PUBLIC_STRINGS

# Stream property tags ([MS-PST] §2.4.7, [MS-OXPROPS]).
PID_NAMEID_GUID = make_tag(0x0002, PropType.BINARY)    # 0x00020102
PID_NAMEID_ENTRY = make_tag(0x0003, PropType.BINARY)   # 0x00030102
PID_NAMEID_STRING = make_tag(0x0004, PropType.BINARY)  # 0x00040102

_NAMEID_SIZE = 8  # [MS-PST] §2.4.7.1 — each NAMEID entry is 8 bytes.


@dataclass
class NamedProp:
    """A resolved named property ([MS-PST] §2.4.7.1).

    Attributes:
        npid: The named-property id (``0x8000 + wPropIdx``).
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
    """Resolve NPIDs (``0x8000+``) to ``(GUID, lid|name)`` for a PST store.

    Built from the ``NID_NAME_TO_ID_MAP`` (0x61) Property Context.  A
    missing/corrupt map is tolerated: the map is simply empty and
    :meth:`resolve` returns ``None`` for every NPID (caller flags
    ``NAMEID_MISSING``).
    """

    def __init__(self, *, sink: Optional[WarningSink] = None) -> None:
        self.sink = sink if sink is not None else WarningSink()
        self._by_npid: dict[int, NamedProp] = {}

    # -- construction -----------------------------------------------------
    @classmethod
    def from_pc(cls, pc: Optional[MapiObject], *,
                sink: Optional[WarningSink] = None) -> "NamedPropMap":
        """Build a map from the name-to-id-map :class:`MapiObject` (NID 0x61).

        Args:
            pc: The parsed ``NID_NAME_TO_ID_MAP`` Property Context, or ``None``
                if the map node was absent.
            sink: Optional warning sink.

        Returns:
            A populated :class:`NamedPropMap` (possibly empty), warning
            ``NAMEID_MISSING`` when the map cannot be read.
        """
        self = cls(sink=sink)
        if pc is None:
            self.sink.warn(WarnCode.NAMEID_MISSING, "NID 0x61 absent",
                           where="name-to-id map")
            return self
        guid_v = pc.get_tag(PID_NAMEID_GUID)
        entry_v = pc.get_tag(PID_NAMEID_ENTRY)
        string_v = pc.get_tag(PID_NAMEID_STRING)
        guid_stream = guid_v.raw if guid_v is not None else b""
        entry_stream = entry_v.raw if entry_v is not None else b""
        string_stream = string_v.raw if string_v is not None else b""
        return self._parse(guid_stream, entry_stream, string_stream)

    @classmethod
    def from_streams(cls, guid_stream: bytes, entry_stream: bytes,
                     string_stream: bytes, *,
                     sink: Optional[WarningSink] = None) -> "NamedPropMap":
        """Build a map from the three raw streams directly (test/recovery use)."""
        return cls(sink=sink)._parse(guid_stream or b"", entry_stream or b"",
                                     string_stream or b"")

    def _parse(self, guid_stream: bytes, entry_stream: bytes,
               string_stream: bytes) -> "NamedPropMap":
        if not entry_stream:
            self.sink.warn(WarnCode.NAMEID_MISSING, "empty entry stream",
                           where="name-to-id map")
            return self
        guids = self._parse_guid_stream(guid_stream)
        n = len(entry_stream) // _NAMEID_SIZE
        for i in range(n):
            off = i * _NAMEID_SIZE
            id_or_off, packed, w_prop_idx = struct.unpack_from(
                "<IHH", entry_stream, off)
            n_flag = packed & 0x0001
            guid_idx = packed >> 1
            guid = self._resolve_guid(guid_idx, guids)
            npid = 0x8000 + w_prop_idx
            if n_flag:
                name = self._read_string(string_stream, id_or_off)
                self._by_npid[npid] = NamedProp(npid=npid, guid=guid, name=name)
            else:
                self._by_npid[npid] = NamedProp(npid=npid, guid=guid, lid=id_or_off)
        return self

    @staticmethod
    def _parse_guid_stream(raw: bytes) -> list[str]:
        """Split the GUID stream into canonical GUID strings ([MS-PST] §2.4.7.2)."""
        out: list[str] = []
        for i in range(0, len(raw) - 15, 16):
            out.append(namedprops.guid_bytes_to_str(raw[i:i + 16]))
        return out

    def _resolve_guid(self, guid_idx: int, guids: list[str]) -> str:
        """Map a ``wGuid`` index to a GUID string (Appendix A H17).

        ``0`` => none (treated as PS_MAPI sentinel), ``1`` => PS_MAPI, ``2`` =>
        PS_PUBLIC_STRINGS, ``>= 3`` => ``GuidStream[guid_idx - 3]``.
        """
        if guid_idx <= 1:
            return PS_MAPI
        if guid_idx == 2:
            return PS_PUBLIC_STRINGS
        sidx = guid_idx - 3
        if 0 <= sidx < len(guids):
            return guids[sidx]
        self.sink.warn(WarnCode.NAMEID_MISSING,
                       f"wGuid index {guid_idx} out of range ({len(guids)} guids)",
                       where="name-to-id map")
        return PS_MAPI

    @staticmethod
    def _read_string(raw: bytes, offset: int) -> Optional[str]:
        """Read a counted UTF-16LE string at ``offset`` ([MS-PST] §2.4.7.4).

        Layout: u32 byte-length, then that many UTF-16LE bytes.
        """
        if offset + 4 > len(raw):
            return None
        (cb,) = struct.unpack_from("<I", raw, offset)
        chunk = raw[offset + 4:offset + 4 + cb]
        return chunk.decode("utf-16-le", "replace")

    # -- lookups ----------------------------------------------------------
    def resolve(self, npid: int) -> Optional[NamedProp]:
        """Resolve an NPID (``0x8000+``) to its :class:`NamedProp`, or ``None``."""
        return self._by_npid.get(npid)

    def label(self, npid: int) -> Optional[str]:
        """Human label for an NPID via :mod:`pstforensic.catalog`, else ``None``."""
        np = self.resolve(npid)
        if np is None:
            return None
        if np.is_string:
            return np.name
        if np.lid is not None:
            friendly = namedprops.lid_name(np.guid, np.lid)
            if friendly:
                return friendly
            set_label = namedprops.set_name(np.guid) or np.guid
            return f"{set_label}:0x{np.lid:04X}"
        return namedprops.set_name(np.guid) or np.guid

    def __len__(self) -> int:
        return len(self._by_npid)
