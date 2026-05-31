"""GUID rendering ([MS-DTYP] GUID; PLAN §9.4).

A MAPI/Windows GUID is stored mixed-endian: the first three groups (Data1 u32,
Data2 u16, Data3 u16) are little-endian, and the final 8 bytes (Data4) are
stored in order. The RFC-4122 textual form re-orders the first three groups to
big-endian:

    Data1(LE u32)-Data2(LE u16)-Data3(LE u16)-Data4[0:2]-Data4[2:8]

Pure, no I/O. Well-known-set annotation is supplied by the caller (the catalog
layer) so this module stays free of catalog data.
"""
from __future__ import annotations

from typing import Mapping, Optional


def guid(b: bytes, known: Optional[Mapping[str, str]] = None) -> str:
    """Render 16 GUID bytes to the canonical RFC-4122 mixed-endian string.

    :param b: exactly 16 bytes (less is padded, more is truncated to 16).
    :param known: optional ``{guid_string: friendly_name}`` map; when the
        rendered GUID is present, the friendly name is appended in parentheses
        (e.g. ``"00020329-...  (PS_PUBLIC_STRINGS)"``). Keeps the renderer pure
        while letting the catalog annotate well-known set GUIDs (PLAN §9.4).
    :returns: a lowercase ``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`` string,
        optionally with a ``  (NAME)`` suffix. Short input yields ``"(invalid)"``.
    """
    if not isinstance(b, (bytes, bytearray)) or len(b) < 16:
        return "(invalid guid)"
    raw = bytes(b[:16])
    data1 = int.from_bytes(raw[0:4], "little")
    data2 = int.from_bytes(raw[4:6], "little")
    data3 = int.from_bytes(raw[6:8], "little")
    data4 = raw[8:16]
    s = (
        f"{data1:08x}-{data2:04x}-{data3:04x}-"
        f"{data4[0]:02x}{data4[1]:02x}-"
        f"{data4[2]:02x}{data4[3]:02x}{data4[4]:02x}{data4[5]:02x}{data4[6]:02x}{data4[7]:02x}"
    )
    if known:
        # Match case-insensitively against both bare and brace-wrapped forms.
        name = known.get(s) or known.get(s.upper()) or known.get("{" + s + "}")
        if name:
            return f"{s}  ({name})"
    return s
