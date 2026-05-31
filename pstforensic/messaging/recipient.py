"""Recipient builder — one :class:`MapiRecipient` per recipient-TC row (PLAN §6.4).

A message's recipients live in the **Recipient Table Context** in its subnode
tree (local NID template ``0x692``, [MS-PST] §2.4.5.3).  Each TC row is already a
:class:`~pstforensic.mapi.MapiObject`; this module simply promotes it to a
:class:`~pstforensic.mapi.MapiRecipient` and lifts the recipient-type out
([MS-OXOMSG] §2.2.3.1: ``1=To``, ``2=Cc``, ``3=Bcc``).
"""
from __future__ import annotations

from typing import Optional

from ..mapi import MapiObject, MapiRecipient

# PidTagRecipientType ([MS-OXOMSG] §2.2.3.1).
PID_RECIPIENT_TYPE = 0x0C15


def build_recipient(row: MapiObject,
                    renderer_installer=None) -> MapiRecipient:
    """Promote a recipient-TC :class:`MapiObject` row to a :class:`MapiRecipient`.

    Args:
        row: One Recipient-TC row parsed by the LTP layer.
        renderer_installer: Optional callable wiring ``row._renderer`` so
            ``recipient.render(tag)`` yields human-readable values.

    Returns:
        A :class:`MapiRecipient` carrying every cell of the row plus the decoded
        ``recipient_type``.
    """
    recip = MapiRecipient(props=row.props, flags=row.flags, nid=row.nid)
    recip.recipient_type = _scalar_u32(recip, PID_RECIPIENT_TYPE)
    if renderer_installer is not None:
        renderer_installer(recip)
    return recip


def _scalar_u32(obj: MapiObject, prop_id: int) -> Optional[int]:
    """Read an inline u32 property value, or ``None`` if absent/short."""
    v = obj.by_id(prop_id)
    if v is None or len(v.raw) < 4:
        return None
    return int.from_bytes(v.raw[:4], "little")
