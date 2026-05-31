"""Pure human-readable renderers for MAPI values (PLAN §9).

This subpackage turns raw MAPI property bytes into analyst-readable Python
values. It performs **no I/O**: every function takes bytes (or an already-built
:class:`~pstforensic.mapi.MapiObject`) and returns plain values.

Public surface:
  * :func:`filetime`, :func:`apptime` (render.filetime)
  * :func:`guid` (render.guid)
  * :func:`entryid` (render.entryid)
  * :func:`decompress_rtf` (render.rtf)
  * :func:`conversation_index` (render.convindex)
  * :func:`decode_string` (render.strings)
  * :func:`render_value` — type-dispatched value renderer
  * :func:`install_renderer` — wires ``MapiObject._renderer``
"""
from __future__ import annotations

import struct
from typing import Any, Optional

from ..mapi import MapiObject, MapiValue
from ..proptypes import PropType, base_type, is_multivalue
from .convindex import conversation_index
from .entryid import entryid
from .filetime import apptime, filetime, ole_date
from .guid import guid
from .rtf import decompress_rtf
from .strings import decode_string, resolve_codepage

__all__ = [
    "filetime",
    "apptime",
    "ole_date",
    "guid",
    "entryid",
    "decompress_rtf",
    "conversation_index",
    "decode_string",
    "render_value",
    "render_currency",
    "render_binary_preview",
    "install_renderer",
]

# Well-known PidTag ids consulted by the string-codepage precedence (§9.7).
_PID_INTERNET_CPID = 0x3FDE
_PID_MESSAGE_CPID = 0x3FFD
_PID_MESSAGE_LOCALE = 0x3FF1
_PID_CONVERSATION_INDEX = 0x0071

# Binary magic-number annotations for PT_BINARY previews (§9.8).
_MAGICS: list[tuple[bytes, str]] = [
    (b"\xff\xd8\xff", "JPEG"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"GIF8", "GIF"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP/OOXML"),
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE/DOS"),
    (b"\xd0\xcf\x11\xe0", "OLE/CFBF"),
    (b"{\\rtf", "RTF"),
]


def render_currency(raw: bytes | int) -> str:
    """Render PtypCurrency: signed int64 scaled by 10000 -> 4-decimal string.

    No currency symbol (Appendix A H11). E.g. ``123400`` -> ``"12.3400"``.
    """
    if isinstance(raw, (bytes, bytearray)):
        if len(raw) < 8:
            return ""
        val = struct.unpack_from("<q", bytes(raw), 0)[0]
    else:
        val = int(raw)
    neg = val < 0
    val = abs(val)
    whole, frac = divmod(val, 10000)
    s = f"{whole}.{frac:04d}"
    return f"-{s}" if neg else s


def render_binary_preview(raw: bytes, max_bytes: int = 64) -> str:
    """Hex + ASCII preview of binary data with a magic-number annotation (§9.8)."""
    if not raw:
        return "(empty)"
    raw = bytes(raw)
    annotation = ""
    for sig, name in _MAGICS:
        if raw.startswith(sig):
            annotation = f" [{name}]"
            break
    head = raw[:max_bytes]
    hexs = head.hex(" ")
    ascii_s = "".join(chr(c) if 32 <= c < 127 else "." for c in head)
    more = "…" if len(raw) > max_bytes else ""
    return f"{len(raw)}B{annotation} {hexs}{more}  |{ascii_s}{more}|"


def render_value(mapi_obj: MapiObject, tag: int) -> Any:
    """Render the value at ``tag`` of ``mapi_obj`` to a human-readable Python value.

    Dispatch is by MAPI property *type* (PLAN §9.8: every PtypXxx and its
    ``0x1000`` MV variant has a decoder). Multi-value types render to a list of
    per-element rendered values. The decoded result is memoized on the
    :class:`MapiValue` via ``set_decoded``.

    :param mapi_obj: the property bag.
    :param tag: the full ``(prop_id<<16)|prop_type`` tag.
    :returns: the rendered value (type depends on the property), or ``None`` if
        the tag is absent.
    """
    v = mapi_obj.get_tag(tag)
    if v is None:
        # Fall back to id lookup (tag may be id-only).
        v = mapi_obj.by_id((tag >> 16) & 0xFFFF) if tag <= 0xFFFF else mapi_obj.by_id(
            (tag >> 16) & 0xFFFF
        )
    if v is None:
        return None
    if v._decoded_set:
        return v._decoded

    ptype = v.prop_type
    bt = base_type(ptype)

    # Multi-value: render each element with the base type.
    if is_multivalue(ptype) and v.elements is not None:
        rendered = [_render_scalar(mapi_obj, v, el, bt) for el in v.elements]
        return v.set_decoded(rendered)

    result = _render_scalar(mapi_obj, v, v.raw, bt)
    return v.set_decoded(result)


def _render_scalar(
    mapi_obj: MapiObject, v: MapiValue, raw: bytes, bt: int
) -> Any:
    """Render a single (non-MV) scalar value of base type ``bt``."""
    if bt == PropType.STRING or bt == PropType.STRING8:
        cp = _resolve_cp(mapi_obj)
        from .strings import decode_string_ex

        d = decode_string_ex(raw, bt, codepage=cp)
        v.encoding = d.encoding
        return d.text

    if bt == PropType.TIME:
        return filetime(raw)

    if bt == PropType.GUID:
        return guid(raw)

    if bt == PropType.BOOLEAN:
        return bool(raw[0]) if raw else False

    if bt == PropType.INTEGER16:
        return int.from_bytes(raw[:2], "little", signed=True) if len(raw) >= 2 else None

    if bt == PropType.INTEGER32 or bt == PropType.ERRORCODE:
        return int.from_bytes(raw[:4], "little", signed=True) if len(raw) >= 4 else None

    if bt == PropType.INTEGER64:
        return int.from_bytes(raw[:8], "little", signed=True) if len(raw) >= 8 else None

    if bt == PropType.FLOATING32:
        return struct.unpack_from("<f", raw, 0)[0] if len(raw) >= 4 else None

    if bt == PropType.FLOATING64:
        return struct.unpack_from("<d", raw, 0)[0] if len(raw) >= 8 else None

    if bt == PropType.CURRENCY:
        return render_currency(raw)

    if bt == PropType.FLOATINGTIME:
        return apptime(raw)

    if bt == PropType.BINARY:
        # Special-case conversation index for a richer render.
        if v.prop_id == _PID_CONVERSATION_INDEX:
            return conversation_index(raw)
        return render_binary_preview(raw)

    # PT_OBJECT / unknown: hand back raw bytes.
    return raw


def _resolve_cp(mapi_obj: MapiObject) -> int:
    """Resolve the PT_STRING8 codepage for ``mapi_obj`` (§9.7 precedence)."""
    def _u32(pid: int) -> Optional[int]:
        mv = mapi_obj.by_id(pid)
        if mv is None or len(mv.raw) < 4:
            return None
        return int.from_bytes(mv.raw[:4], "little")

    return resolve_codepage(
        internet_cpid=_u32(_PID_INTERNET_CPID),
        message_cpid=_u32(_PID_MESSAGE_CPID),
        store_cpid=None,
        locale_id=_u32(_PID_MESSAGE_LOCALE),
    )


def install_renderer(mapi_obj: MapiObject) -> MapiObject:
    """Wire :func:`render_value` into ``mapi_obj._renderer``.

    After this call, ``mapi_obj.render(tag)`` produces human-readable values.
    Returns the same object for chaining.
    """
    mapi_obj._renderer = render_value
    return mapi_obj
