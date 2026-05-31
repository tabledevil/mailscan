"""Message reader — build a :class:`MapiMessage` from a message node (PLAN §6.3).

A message is a top-level node (``nidType 0x04`` normal / ``0x08`` FAI) whose data
stream is a Property Context and whose subnode tree holds:

  * Recipient TC — subnode local NID template ``0x692`` ([MS-PST] §2.4.5.3).
  * Attachment table TC — subnode local NID template ``0x671`` ([MS-PST] §2.4.6.1).
  * One Attachment PC per attachment (subnode ``nidType 0x05``), whose ``dwRowID``
    is given by the attachment table row ([MS-PST] §2.4.6.2).
  * For an embedded message (``PidTagAttachMethod == 5``), the attachment PC holds
    ``PidTagAttachDataObject`` (``0x3701000D``) whose value is a *further* subnode
    NID rooting the embedded message's own PC — recursed into (Appendix A H7).

Recipients/attachments are parsed eagerly here (the synth fixtures are small); a
production reader would defer them (PLAN §6.3 laziness note), but the public
shape is identical.
"""
from __future__ import annotations

import struct
from typing import Optional

from ..exceptions import WarnCode, WarningSink
from ..ltp.pc import PropertyContext
from ..ltp.tc import TableContext, PID_LTP_ROW_ID
from ..mapi import MapiMessage, MapiObject
from ..ndb.nodedb import NodeRef
from ..proptypes import make_tag, PropType
from ..variant import Variant
from .attachment import (
    TAG_ATTACH_DATA_BIN,
    TAG_ATTACH_DATA_OBJ,
    build_attachment,
)
from .recipient import build_recipient

# Subnode local-NID templates ([MS-PST] §2.4.5.3 / §2.4.6.1).
SUBNODE_RECIPIENT_TC = 0x692
SUBNODE_ATTACHMENT_TC = 0x671

# dwRowID column id (PidTagLtpRowId) used to read a TC row's encoded child NID.
_PID_LTP_ROW_ID = PID_LTP_ROW_ID  # 0x67480003

_MAX_EMBED_DEPTH = 16  # recursion guard for embedded messages.


def build_message(noderef: NodeRef, variant: Variant, *,
                  sink: WarningSink,
                  renderer_installer=None,
                  depth: int = 0) -> MapiMessage:
    """Parse a message ``noderef`` into a fully-populated :class:`MapiMessage`.

    Args:
        noderef: The message node (PC + subnode tree).
        variant: The store variant (ANSI / Unicode / 4K).
        sink: Warning sink shared down the parse.
        renderer_installer: ``render.install_renderer`` (or compatible) wired
            into every produced object so ``.render(tag)`` works.
        depth: Embedded-message recursion depth (internal).

    Returns:
        A :class:`MapiMessage` with ``recipients``, ``attachments`` and
        ``embedded_messages`` populated.
    """
    pc = PropertyContext.from_node(noderef, variant, sink=sink)
    msg = MapiMessage(props=pc.props, flags=pc.flags, nid=pc.nid)
    if renderer_installer is not None:
        renderer_installer(msg)

    subs = noderef.subnodes()

    # -- recipients (subnode 0x692; required → warn if absent) --
    rcpt_ref = subs.get(SUBNODE_RECIPIENT_TC)
    if rcpt_ref is not None:
        for row in TableContext.from_node(rcpt_ref, variant, sink=sink):
            msg.recipients.append(build_recipient(row, renderer_installer))
    else:
        sink.warn(WarnCode.TRUNCATED, "recipient TC (subnode 0x692) absent",
                  where=f"msg nid={noderef.nid:#x}")

    # -- attachments (subnode 0x671; optional) --
    att_ref = subs.get(SUBNODE_ATTACHMENT_TC)
    if att_ref is not None:
        for row in TableContext.from_node(att_ref, variant, sink=sink):
            att_nid = _row_id(row)
            att_pc_ref = subs.get(att_nid) if att_nid is not None else None
            if att_pc_ref is None:
                sink.warn(WarnCode.OUT_OF_BOUNDS,
                          f"attachment PC subnode {att_nid:#x} absent"
                          if att_nid is not None else "attachment row missing dwRowID",
                          where=f"msg nid={noderef.nid:#x}")
                continue
            att = _build_one_attachment(att_pc_ref, variant, sink=sink,
                                        renderer_installer=renderer_installer,
                                        depth=depth)
            msg.attachments.append(att)
            if att.embedded is not None:
                msg.embedded_messages.append(att.embedded)

    return msg


def _build_one_attachment(att_pc_ref: NodeRef, variant: Variant, *,
                          sink: WarningSink, renderer_installer, depth: int):
    """Parse one attachment PC; recurse for embedded messages (method 5)."""
    pc = PropertyContext.from_node(att_pc_ref, variant, sink=sink)

    embedded: Optional[MapiMessage] = None
    open_data = None

    # Embedded message: PidTagAttachDataObject (0x3701000D) → subnode PC.
    data_obj = pc.get_tag(TAG_ATTACH_DATA_OBJ)
    if data_obj is not None:
        embed_nid = _EMBED_SUBNODE_NID
        embed_ref = att_pc_ref.subnodes().get(embed_nid)
        if embed_ref is not None:
            if depth + 1 > _MAX_EMBED_DEPTH:
                sink.warn(WarnCode.CYCLE_DETECTED,
                          f"embedded-message depth exceeded {_MAX_EMBED_DEPTH}",
                          where=f"attach nid={att_pc_ref.nid:#x}")
            else:
                embedded = build_message(
                    embed_ref, variant, sink=sink,
                    renderer_installer=renderer_installer, depth=depth + 1)
        elif embed_nid:
            sink.warn(WarnCode.OUT_OF_BOUNDS,
                      f"embedded-message subnode {embed_nid:#x} absent",
                      where=f"attach nid={att_pc_ref.nid:#x}")

    # By-value attachment: expose the binary body lazily.
    data_bin = pc.get_tag(TAG_ATTACH_DATA_BIN)
    if data_bin is not None and embedded is None:
        raw = data_bin.raw
        open_data = lambda r=raw: r

    return build_attachment(pc, embedded=embedded, open_data=open_data,
                            renderer_installer=renderer_installer)


# Conventional embedded-message subnode local NID = the full object tag
# 0x3701000D ([MS-PST] §2.4.6.2; Appendix A H7).  The attachment PC's
# PidTagAttachDataObject HNID resolves to this subnode whose data stream is the
# embedded message's own Property Context.
_EMBED_SUBNODE_NID = make_tag(0x3701, PropType.OBJECT)  # 0x3701000D


def _row_id(row: MapiObject) -> Optional[int]:
    """Return a TC row's ``dwRowID`` (PidTagLtpRowId), which encodes the child NID."""
    v = row.get_tag(_PID_LTP_ROW_ID) or row.by_id(0x6748)
    if v is None or len(v.raw) < 4:
        return None
    return struct.unpack_from("<I", v.raw, 0)[0]
