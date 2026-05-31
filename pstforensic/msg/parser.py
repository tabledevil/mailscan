"""Native MSG parser: ``open_msg(source) -> MapiMessage`` (PLAN §10.1, App. A H12).

Parses an Outlook ``.msg`` (CFBF/OLE) file into the shared
:class:`~pstforensic.mapi.MapiMessage` model so every ``render``/``catalog``
capability works identically for MSG and PST (G6).

Key layout facts (Appendix A H12, [MS-OXMSG] §2.4):

  * ``__properties_version1.0`` begins with a header whose size depends on the
    storage **role** — **8 bytes** for the top-level message storage, **24
    bytes** for embedded-message / recipient / attachment storages.  This is NOT
    an ANSI/Unicode split.
  * After the header come fixed **16-byte** property entries:
    ``propTag(4) | flags(4) | value-or-reserved(8)``.  Fixed types ≤ 8 bytes are
    stored inline; variable/large types are referenced by a ``__substg1.0_*``
    stream.
  * Stream naming is ``__substg1.0_%08X`` using the **full 8-hex** property tag
    (``id<<16 | type``), e.g. subject = ``__substg1.0_0037001F``.  There is no
    ``0x1000`` transform.  MV instances get an index suffix ``-%08X``.
"""
from __future__ import annotations

import re
import struct
from typing import Optional

from ..exceptions import NotAMsgError, WarnCode, WarningSink
from ..mapi import MapiAttachment, MapiMessage, MapiRecipient, MapiValue
from ..proptypes import (
    PropType,
    base_type,
    fixed_size,
    is_multivalue,
    make_tag,
    split_tag,
)
from .cfbf import CfbfContainer
from .nameid import NamedPropMap

# -- well-known constants ---------------------------------------------------

_PROPERTIES_STREAM = "__properties_version1.0"
_SUBSTG_PREFIX = "__substg1.0_"
_NAMEID_STORAGE = "__nameid_version1.0"

# Property-entry geometry ([MS-OXMSG] §2.4.2.x, Appendix A H12).
_ENTRY_SIZE = 16
_HEADER_TOP = 8       # top-level message store
_HEADER_SUB = 24      # embedded / recipient / attachment storages

# PidTag ids referenced by the parser.
PID_RECIPIENT_TYPE = 0x0C15      # PidTagRecipientType (PtypInteger32)
PID_ATTACH_METHOD = 0x3705       # PidTagAttachMethod (PtypInteger32)
PID_ATTACH_DATA_OBJ = 0x3701     # PidTagAttachDataObject (binary or embedded msg)
PID_EMAIL_ADDRESS = 0x3003       # PidTagEmailAddress
PID_SMTP_ADDRESS = 0x39FE        # PidTagSmtpAddress
PID_ENTRYID = 0x0FFF             # PidTagEntryId

# Embedded message attachment: __substg1.0_3701000D is a *storage* (PtypObject).
_ATTACH_DATA_OBJECT_TAG = make_tag(PID_ATTACH_DATA_OBJ, PropType.OBJECT)  # 0x3701000D

# AttachMethod values ([MS-OXCMSG] §2.2.2.9).
ATTACH_BY_VALUE = 1
ATTACH_EMBEDDED_MSG = 5
ATTACH_OLE = 6

_RECIP_RE = re.compile(r"^__recip_version1\.0_#?([0-9A-Fa-f]{8})$")
_ATTACH_RE = re.compile(r"^__attach_version1\.0_#?([0-9A-Fa-f]{8})$")
_SUBSTG_RE = re.compile(
    r"^__substg1\.0_([0-9A-Fa-f]{8})(?:-([0-9A-Fa-f]{8}))?$"
)

_MAX_EMBED_DEPTH = 16  # recursion guard for embedded messages (sanity bound).


class _StorageReader:
    """Reads one MSG *storage* (root, recipient, attachment, or embedded msg).

    A storage is addressed by a CFBF prefix path ("" for root).  This class
    pulls the ``__properties_version1.0`` entries and the ``__substg1.0_*``
    streams under that prefix and folds them into a :class:`MapiObject`.
    """

    def __init__(
        self,
        cfbf: CfbfContainer,
        prefix: str,
        *,
        header_size: int,
        sink: WarningSink,
    ) -> None:
        self.cfbf = cfbf
        self.prefix = prefix
        self.header_size = header_size
        self.sink = sink

    def _path(self, leaf: str) -> str:
        return f"{self.prefix}/{leaf}" if self.prefix else leaf

    def populate(self, obj) -> None:
        """Fill ``obj.props`` from this storage's properties + substg streams."""
        # 1) Index the variable/binary streams available in this storage.
        substg: dict[int, dict[Optional[int], bytes]] = {}
        for name in self.cfbf.streams(self.prefix):
            m = _SUBSTG_RE.match(name)
            if not m:
                continue
            tag = int(m.group(1), 16)
            mv_index = int(m.group(2), 16) if m.group(2) else None
            data = self.cfbf.read_stream(self._path(name))
            if data is None:
                continue
            substg.setdefault(tag, {})[mv_index] = data

        # 2) Walk the fixed __properties entries.
        props_raw = self.cfbf.read_stream(self._path(_PROPERTIES_STREAM))
        if props_raw is None:
            self.sink.warn(
                WarnCode.OUT_OF_BOUNDS,
                "missing __properties_version1.0",
                where=self.prefix or "(root)",
            )
            props_raw = b""

        body = props_raw[self.header_size :]
        n = len(body) // _ENTRY_SIZE
        consumed_substg: set[int] = set()
        for i in range(n):
            off = i * _ENTRY_SIZE
            tag, _flags = struct.unpack_from("<II", body, off)
            value8 = body[off + 8 : off + 16]
            pid, ptype = split_tag(tag)
            self._fold_entry(obj, tag, pid, ptype, value8, substg, consumed_substg)

        # 3) Some producers omit certain props from __properties but still ship
        #    the substg stream (notably string envelope fields).  Fold any
        #    leftover streams so nothing is silently dropped.
        for tag, by_index in substg.items():
            if tag in consumed_substg:
                continue
            self._fold_stream_only(obj, tag, by_index)

    def _fold_entry(
        self,
        obj,
        tag: int,
        pid: int,
        ptype: int,
        value8: bytes,
        substg: dict,
        consumed: set,
    ) -> None:
        """Fold a single 16-byte property entry into ``obj``."""
        bt = base_type(ptype)
        fsz = fixed_size(bt)

        if not is_multivalue(ptype) and fsz is not None and fsz <= 8:
            # Inline fixed value (Appendix A H12).  BOOLEAN stored in 2 bytes,
            # but value8[:fsz] is the canonical truncation.
            raw = value8[:fsz]
            obj.add(MapiValue(tag=tag, raw=raw))
            return

        # Variable / large / MV: reference the substg stream(s).
        consumed.add(tag)
        streams = substg.get(tag)
        if streams is None:
            # The entry declares it but the stream is absent — keep an empty
            # placeholder rather than dropping the tag.
            obj.add(MapiValue(tag=tag, raw=b""))
            return
        self._fold_stream_only(obj, tag, streams)

    def _fold_stream_only(self, obj, tag: int, by_index: dict) -> None:
        """Fold substg stream data (with optional MV indices) into ``obj``."""
        pid, ptype = split_tag(tag)
        if is_multivalue(ptype) and any(k is not None for k in by_index):
            elements = [by_index[k] for k in sorted(k for k in by_index if k is not None)]
            obj.add(
                MapiValue(
                    tag=tag,
                    raw=b"".join(elements),
                    elements=elements,
                )
            )
        else:
            # Non-MV (or MV packed in a single stream): take index None if
            # present, else the only stream.
            if None in by_index:
                raw = by_index[None]
            else:
                raw = next(iter(by_index.values()))
            obj.add(MapiValue(tag=tag, raw=raw))


def _scalar_u32(obj, prop_id: int) -> Optional[int]:
    """Read an inline u32 property value, or ``None`` if absent/short."""
    v = obj.by_id(prop_id)
    if v is None or len(v.raw) < 4:
        return None
    return int.from_bytes(v.raw[:4], "little")


def _parse_recipient(
    cfbf: CfbfContainer, prefix: str, *, sink: WarningSink
) -> MapiRecipient:
    """Parse a ``__recip_version1.0_#*`` storage into a :class:`MapiRecipient`.

    [MS-OXMSG] §2.2.1: recipient storages use the 24-byte sub-storage header.
    """
    recip = MapiRecipient()
    _StorageReader(cfbf, prefix, header_size=_HEADER_SUB, sink=sink).populate(recip)
    recip.recipient_type = _scalar_u32(recip, PID_RECIPIENT_TYPE)
    return recip


def _parse_attachment(
    cfbf: CfbfContainer, prefix: str, *, sink: WarningSink, depth: int
) -> MapiAttachment:
    """Parse a ``__attach_version1.0_#*`` storage into a :class:`MapiAttachment`.

    [MS-OXMSG] §2.2.2: attachment storages use the 24-byte sub-storage header.
    An embedded message (``PidTagAttachMethod == 5``) lives in the
    ``__substg1.0_3701000D`` **sub-storage** and is parsed recursively.
    """
    att = MapiAttachment()
    _StorageReader(cfbf, prefix, header_size=_HEADER_SUB, sink=sink).populate(att)
    att.method = _scalar_u32(att, PID_ATTACH_METHOD)

    # Embedded message: __substg1.0_3701000D is a storage, not a stream.
    embed_path = f"{prefix}/{_SUBSTG_PREFIX}{_ATTACH_DATA_OBJECT_TAG:08X}"
    if cfbf.has_storage(embed_path):
        if depth + 1 > _MAX_EMBED_DEPTH:
            sink.warn(
                WarnCode.CYCLE_DETECTED,
                f"embedded-message depth exceeded {_MAX_EMBED_DEPTH}",
                where=embed_path,
            )
        else:
            att.embedded = _parse_message(
                cfbf, embed_path, header_size=_HEADER_SUB, sink=sink, depth=depth + 1
            )
            if att.method is None:
                att.method = ATTACH_EMBEDDED_MSG
    else:
        # By-value attachment: expose the data stream lazily.
        data_tag = make_tag(PID_ATTACH_DATA_OBJ, PropType.BINARY)  # 0x37010102
        data_path = f"{prefix}/{_SUBSTG_PREFIX}{data_tag:08X}"
        if cfbf.has_stream(data_path):
            att.open_data = lambda p=data_path: cfbf.read_stream(p) or b""

    return att


def _parse_message(
    cfbf: CfbfContainer,
    prefix: str,
    *,
    header_size: int,
    sink: WarningSink,
    depth: int,
) -> MapiMessage:
    """Parse one message storage (root or embedded) into a :class:`MapiMessage`."""
    msg = MapiMessage()
    _StorageReader(cfbf, prefix, header_size=header_size, sink=sink).populate(msg)

    # Named-property map (shared by every property render for this message).
    msg.nameid = _build_nameid(cfbf, prefix, sink=sink)  # type: ignore[attr-defined]

    # Recipients.
    for name in sorted(cfbf.storages(prefix)):
        if _RECIP_RE.match(name):
            rpath = f"{prefix}/{name}" if prefix else name
            msg.recipients.append(_parse_recipient(cfbf, rpath, sink=sink))

    # Attachments.
    for name in sorted(cfbf.storages(prefix)):
        if _ATTACH_RE.match(name):
            apath = f"{prefix}/{name}" if prefix else name
            att = _parse_attachment(cfbf, apath, sink=sink, depth=depth)
            msg.attachments.append(att)
            if att.embedded is not None:
                msg.embedded_messages.append(att.embedded)

    return msg


def _build_nameid(
    cfbf: CfbfContainer, prefix: str, *, sink: WarningSink
) -> NamedPropMap:
    """Build the :class:`NamedPropMap` from this storage's ``__nameid`` streams."""
    base = f"{prefix}/{_NAMEID_STORAGE}" if prefix else _NAMEID_STORAGE
    guid = cfbf.read_stream(f"{base}/{_SUBSTG_PREFIX}00020102")
    entry = cfbf.read_stream(f"{base}/{_SUBSTG_PREFIX}00030102")
    string = cfbf.read_stream(f"{base}/{_SUBSTG_PREFIX}00040102")
    return NamedPropMap.from_streams(guid, entry, string, sink=sink)


def open_msg(
    source,
    *,
    sink: Optional[WarningSink] = None,
) -> MapiMessage:
    """Open an Outlook ``.msg`` file and return its :class:`MapiMessage`.

    Args:
        source: A path, ``bytes`` image, or seekable binary stream of a CFBF MSG.
        sink: Optional :class:`~pstforensic.exceptions.WarningSink`; one is
            created if omitted (reachable afterwards via ``message.flags``-style
            inspection through the returned object's ``nameid``/``sink``).

    Returns:
        A fully-populated :class:`MapiMessage` (recipients, attachments,
        embedded messages, named-property map).

    Raises:
        NotAMsgError: If the bytes are not a CFBF MSG or :mod:`olefile` is
            unavailable.
    """
    sink = sink if sink is not None else WarningSink()
    cfbf = CfbfContainer(source, sink=sink)

    # The root MUST carry the message properties stream to be a real MSG.
    if not cfbf.has_stream(_PROPERTIES_STREAM):
        raise NotAMsgError(f"missing {_PROPERTIES_STREAM}; not an Outlook MSG")

    msg = _parse_message(
        cfbf, "", header_size=_HEADER_TOP, sink=sink, depth=0
    )
    # Stash the sink on the message for downstream warning inspection.
    msg.sink = sink  # type: ignore[attr-defined]
    return msg
