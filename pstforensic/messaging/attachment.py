"""Attachment builder — :class:`MapiAttachment` from an attachment PC (PLAN §6.5).

Each attachment is a Property Context in the message's subnode tree (local NID
``nidType 0x05``, one per attachment — [MS-PST] §2.4.6.2).  The attachment table
TC (subnode ``0x671``) enumerates them; the messaging layer resolves each row's
``dwRowID`` to that attachment PC.

``PidTagAttachMethod`` enum (Appendix A H7; the dossier had embedded/OLE
swapped):

  * ``0`` afNone
  * ``1`` afByValue        → ``PidTagAttachDataBinary`` (``0x37010102``)
  * ``2`` afByReference / ``3`` afByReferenceResolve / ``4`` afByReferenceOnly
  * ``5`` afEmbeddedMessage → nested Message via subnode
          ``PidTagAttachDataObject`` (``0x3701000D``, PtypObject)
  * ``6`` afStorage (OLE / PtypObject)

Full type-qualified tags disambiguate ``0x3701``: ``0x3701000D`` is the embedded
object, ``0x37010102`` is the binary blob.
"""
from __future__ import annotations

from typing import Callable, Optional

from ..mapi import MapiAttachment, MapiMessage, MapiObject
from ..proptypes import make_tag, PropType

# PidTag ids ([MS-OXCMSG] §2.2.2).
PID_ATTACH_METHOD = 0x3705
PID_ATTACH_DATA = 0x3701          # ambiguous w/o a type — use the full tags below
PID_ATTACH_LONG_FILENAME = 0x3707
PID_ATTACH_FILENAME = 0x3704
PID_ATTACH_SIZE = 0x0E20

# Full type-qualified tags (Appendix A H7/H13).
TAG_ATTACH_DATA_BIN = make_tag(PID_ATTACH_DATA, PropType.BINARY)   # 0x37010102
TAG_ATTACH_DATA_OBJ = make_tag(PID_ATTACH_DATA, PropType.OBJECT)   # 0x3701000D

# AttachMethod values (Appendix A H7).
ATTACH_NONE = 0
ATTACH_BY_VALUE = 1
ATTACH_BY_REFERENCE = 2
ATTACH_BY_REFERENCE_RESOLVE = 3
ATTACH_BY_REFERENCE_ONLY = 4
ATTACH_EMBEDDED_MSG = 5
ATTACH_OLE = 6


def build_attachment(
    pc: MapiObject,
    *,
    embedded: Optional[MapiMessage] = None,
    open_data: Optional[Callable[[], bytes]] = None,
    renderer_installer=None,
) -> MapiAttachment:
    """Promote an attachment :class:`MapiObject` (PC) to a :class:`MapiAttachment`.

    Args:
        pc: The parsed attachment Property Context.
        embedded: A nested :class:`MapiMessage` for ``afEmbeddedMessage`` (5).
        open_data: Lazy byte source for an ``afByValue`` (1) attachment body.
        renderer_installer: Optional callable wiring ``pc._renderer``.

    Returns:
        A :class:`MapiAttachment` with ``method``/``embedded``/``open_data`` set.
    """
    att = MapiAttachment(props=pc.props, flags=pc.flags, nid=pc.nid)
    att.method = _scalar_u32(att, PID_ATTACH_METHOD)
    att.embedded = embedded
    att.open_data = open_data
    if att.method is None and embedded is not None:
        att.method = ATTACH_EMBEDDED_MSG
    if renderer_installer is not None:
        renderer_installer(att)
    return att


def attach_filename(att: MapiObject) -> Optional[str]:
    """Best display filename: long filename, else short, else ``None``."""
    for pid in (PID_ATTACH_LONG_FILENAME, PID_ATTACH_FILENAME):
        v = att.by_id(pid)
        if v is not None and v.raw:
            return v.raw.decode("utf-16-le", "replace")
    return None


def _scalar_u32(obj: MapiObject, prop_id: int) -> Optional[int]:
    """Read an inline u32 property value, or ``None`` if absent/short."""
    v = obj.by_id(prop_id)
    if v is None or len(v.raw) < 4:
        return None
    return int.from_bytes(v.raw[:4], "little")
