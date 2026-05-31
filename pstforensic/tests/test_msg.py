"""Tests for the native MSG parser (``pstforensic.msg``).

Coverage (PLAN §10.1, Appendix A H12):
  * ``__properties_version1.0`` header-size by storage role (8B top / 24B sub).
  * 16-byte fixed entries; inline fixed values vs ``__substg1.0_%08X`` streams.
  * Full-tag stream naming (subject = ``__substg1.0_0037001F``).
  * ``__recip_version1.0_#*`` -> :class:`MapiRecipient` (recipient_type).
  * ``__attach_version1.0_#*`` -> :class:`MapiAttachment` (by-value + embedded).
  * Embedded-message recursion via ``__substg1.0_3701000D`` (a *storage*).
  * ``__nameid_version1.0`` named-property resolution (Appendix A H17).

The synth ``build_msg`` only emits a *flat* root (its right-sibling CFBF
directory confuses ``olefile`` past ~3 entries and never writes recipient /
attachment storages).  Per the contract, this test therefore ships a small,
correct CFBF writer (``_MiniCfbf``) that produces a proper [MS-CFB] §2.6.4
red-black-ordered directory ``olefile`` reads reliably, including nested
storages.  We do NOT edit ``synth.py``.
"""
from __future__ import annotations

import struct

import pytest

from pstforensic.exceptions import WarnCode, WarningSink
from pstforensic.mapi import MapiMessage
from pstforensic.msg.nameid import (
    PS_PUBLIC_STRINGS,
    NamedPropMap,
)
from pstforensic.proptypes import PropType, make_tag
from pstforensic.render import install_renderer

olefile = pytest.importorskip("olefile")

from pstforensic.msg.parser import open_msg  # noqa: E402  (after importorskip)


# ---------------------------------------------------------------------------
# A correct minimal CFBF writer (test-only oracle).
# ---------------------------------------------------------------------------
#
# Implements just enough of [MS-CFB] to be read by ``olefile``:
#   * 512-byte sectors; all stream data placed in the mini-stream (< cutoff).
#   * A directory laid out as a proper red-black-ordered tree per §2.6.4:
#     siblings ordered first by UTF-16 name *length*, then by uppercase name.
# This avoids the synth writer's right-sibling-chain limitation.

_ENDOFCHAIN = 0xFFFFFFFE
_FREESECT = 0xFFFFFFFF
_FATSECT = 0xFFFFFFFD
_NOSTREAM = 0xFFFFFFFF
_SECTOR = 512
_MINISECTOR = 64


class _Node:
    """A directory node: a storage (with children) or a stream (with data)."""

    def __init__(self, name: str, is_storage: bool, data: bytes = b"") -> None:
        self.name = name
        self.is_storage = is_storage
        self.data = data
        self.children: list["_Node"] = []
        # filled during layout
        self.index = 0
        self.start = _ENDOFCHAIN
        self.size = 0
        self.child = _NOSTREAM
        self.left = _NOSTREAM
        self.right = _NOSTREAM

    def add(self, node: "_Node") -> "_Node":
        self.children.append(node)
        return node


def _cfb_key(name: str) -> tuple[int, str]:
    """[MS-CFB] §2.6.4 sibling ordering key: (utf16 name length, uppercase)."""
    return (len(name) + 1, name.upper())  # +1 accounts for the NUL terminator


def _build_subtree(nodes: list[_Node]) -> int:
    """Build a balanced BST over sorted ``nodes``; return root index (in self)."""
    nodes = sorted(nodes, key=lambda n: _cfb_key(n.name))

    def rec(lo: int, hi: int) -> int:
        if lo > hi:
            return _NOSTREAM
        mid = (lo + hi) // 2
        n = nodes[mid]
        n.left = rec(lo, mid - 1)
        n.right = rec(mid + 1, hi)
        return n.index

    return rec(0, len(nodes) - 1)


class _MiniCfbf:
    """Assemble a CFBF image from a directory tree rooted at a ``_Node``."""

    def __init__(self, root: _Node) -> None:
        self.root = root
        self.order: list[_Node] = []

    def _assign_indices(self) -> None:
        # BFS to assign stable directory indices (root == 0).
        queue = [self.root]
        while queue:
            n = queue.pop(0)
            n.index = len(self.order)
            self.order.append(n)
            queue.extend(n.children)

    def build(self) -> bytes:
        self._assign_indices()

        # Wire child/left/right pointers.
        for n in self.order:
            if n.children:
                n.child = _build_subtree(n.children)

        # Lay out all stream data into the mini-stream.
        mini = bytearray()
        for n in self.order:
            if not n.is_storage and n is not self.root:
                n.start = len(mini) // _MINISECTOR
                n.size = len(n.data)
                mini += n.data
                mini += b"\x00" * ((-len(n.data)) % _MINISECTOR)

        # mini-FAT chain.
        minifat: list[int] = []
        cursor = 0
        for n in self.order:
            if n.is_storage or n is self.root:
                continue
            nsec = max(1, (len(n.data) + _MINISECTOR - 1) // _MINISECTOR)
            for j in range(nsec):
                minifat.append(cursor + j + 1 if j < nsec - 1 else _ENDOFCHAIN)
            cursor += nsec
        while len(minifat) % (_SECTOR // 4):
            minifat.append(_FREESECT)

        # Root entry points at the mini-stream big-sector chain.
        self.root.is_storage = True
        self.root.size = len(mini)

        dir_bytes = b"".join(self._dir_entry(n) for n in self.order)
        dir_bytes += b"\x00" * ((-len(dir_bytes)) % _SECTOR)
        dir_nsect = len(dir_bytes) // _SECTOR

        # Big-sector layout: [FAT][dir...][minifat...][ministream...]
        fat_sector = 0
        dir_sector = 1
        minifat_sector = dir_sector + dir_nsect
        minifat_bytes = b"".join(struct.pack("<I", x) for x in minifat)
        minifat_bytes += b"\x00" * ((-len(minifat_bytes)) % _SECTOR)
        minifat_nsect = len(minifat_bytes) // _SECTOR
        ministream_start = minifat_sector + minifat_nsect
        mini_bytes = bytes(mini) + b"\x00" * ((-len(mini)) % _SECTOR)
        ministream_nsect = len(mini_bytes) // _SECTOR

        # Root start-sector = first ministream sector.
        if ministream_nsect:
            self.root.start = ministream_start
        else:
            self.root.start = _ENDOFCHAIN
        # Re-emit dir now that root.start is final.
        dir_bytes = b"".join(self._dir_entry(n) for n in self.order)
        dir_bytes += b"\x00" * ((-len(dir_bytes)) % _SECTOR)

        total = ministream_start + ministream_nsect
        fat = [_FREESECT] * (_SECTOR // 4)
        # Ensure FAT covers all sectors (grow if needed; single FAT sector OK
        # for our tiny fixtures).
        fat[fat_sector] = _FATSECT
        for s in range(dir_sector, dir_sector + dir_nsect):
            fat[s] = (s + 1) if s + 1 < dir_sector + dir_nsect else _ENDOFCHAIN
        for s in range(minifat_sector, minifat_sector + minifat_nsect):
            fat[s] = (s + 1) if s + 1 < minifat_sector + minifat_nsect else _ENDOFCHAIN
        for s in range(ministream_start, total):
            fat[s] = (s + 1) if s + 1 < total else _ENDOFCHAIN
        assert total <= len(fat), "fixture too large for single FAT sector"
        fat_bytes = b"".join(struct.pack("<I", x) for x in fat)

        header = self._header(dir_sector, minifat_sector, minifat_nsect, fat_sector)
        return header + fat_bytes + dir_bytes + minifat_bytes + mini_bytes

    @staticmethod
    def _dir_entry(n: _Node) -> bytes:
        nb = n.name.encode("utf-16-le") + b"\x00\x00"
        nb_len = min(len(nb), 64)
        nb = nb[:64].ljust(64, b"\x00")
        etype = 5 if is_root(n) else (1 if n.is_storage else 2)
        color = 1  # black
        return struct.pack(
            "<64sHBBIII16sIQQIQ",
            nb, nb_len, etype, color,
            n.left, n.right, n.child,
            b"\x00" * 16, 0, 0, 0, n.start, n.size,
        )

    @staticmethod
    def _header(dir_sector, minifat_sector, minifat_nsect, fat_sector) -> bytes:
        h = bytearray(512)
        h[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
        struct.pack_into("<H", h, 24, 0x003E)
        struct.pack_into("<H", h, 26, 0x0003)
        struct.pack_into("<H", h, 28, 0xFFFE)
        struct.pack_into("<H", h, 30, 9)
        struct.pack_into("<H", h, 32, 6)
        struct.pack_into("<I", h, 44, 1)            # num FAT sectors
        struct.pack_into("<I", h, 48, dir_sector)   # first dir sector
        struct.pack_into("<I", h, 56, 4096)         # mini cutoff
        struct.pack_into("<I", h, 60, minifat_sector)
        struct.pack_into("<I", h, 64, minifat_nsect)
        struct.pack_into("<I", h, 68, _ENDOFCHAIN)  # first DIFAT
        struct.pack_into("<I", h, 72, 0)            # num DIFAT
        struct.pack_into("<I", h, 76, fat_sector)
        for k in range(1, 109):
            struct.pack_into("<I", h, 76 + k * 4, _FREESECT)
        return bytes(h)


# Module-level marker for the root node (index 0 == Root Entry).
_ROOT_MARKER: "_Node | None" = None


def is_root(n: _Node) -> bool:
    return n is _ROOT_MARKER


def _make_msg_image(root: _Node) -> bytes:
    global _ROOT_MARKER
    _ROOT_MARKER = root
    return _MiniCfbf(root).build()


# ---------------------------------------------------------------------------
# High-level builders for property storages.
# ---------------------------------------------------------------------------


def _properties_stream(header_size: int, props: dict[int, bytes]) -> tuple[bytes, dict]:
    """Build a ``__properties_version1.0`` stream + the substg streams it needs.

    Returns ``(properties_bytes, {stream_name: data})``.  Fixed types <= 8B are
    inlined into the 16-byte entry ([MS-OXMSG] §2.4); everything else is emitted
    as a ``__substg1.0_%08X`` stream and referenced.
    """
    from pstforensic.proptypes import fixed_size, split_tag

    entries = bytearray(b"\x00" * header_size)
    streams: dict[str, bytes] = {}
    for tag in sorted(props):
        value = props[tag]
        _pid, ptype = split_tag(tag)
        fsz = fixed_size(ptype)
        flags = 0x00000006
        if fsz is not None and fsz <= 8:
            val8 = (value + b"\x00" * 8)[:8]
            entries += struct.pack("<II", tag, flags) + val8
        else:
            streams[f"__substg1.0_{tag:08X}"] = value
            entries += struct.pack("<IIII", tag, flags, len(value), 0)
    return bytes(entries), streams


def _add_storage_with_props(
    parent: _Node, storage_name: str, header_size: int, props: dict[int, bytes]
) -> _Node:
    st = parent.add(_Node(storage_name, is_storage=True))
    pbytes, streams = _properties_stream(header_size, props)
    st.add(_Node("__properties_version1.0", is_storage=False, data=pbytes))
    for name, data in streams.items():
        st.add(_Node(name, is_storage=False, data=data))
    return st


def _u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


# ---------------------------------------------------------------------------
# Tag constants used across tests.
# ---------------------------------------------------------------------------

TAG_SUBJECT = make_tag(0x0037, PropType.STRING)       # 0x0037001F
TAG_SENDER_EMAIL = make_tag(0x0C1F, PropType.STRING)  # PidTagSenderEmailAddress
TAG_DISPLAY_TO = make_tag(0x0E04, PropType.STRING)    # PidTagDisplayTo
TAG_BODY = make_tag(0x1000, PropType.STRING)          # PidTagBody
TAG_RECIP_EMAIL = make_tag(0x3003, PropType.STRING)   # PidTagEmailAddress
TAG_RECIP_TYPE = make_tag(0x0C15, PropType.INTEGER32)  # PidTagRecipientType
TAG_ATTACH_FNAME = make_tag(0x3704, PropType.STRING)   # PidTagAttachFilename
TAG_ATTACH_METHOD = make_tag(0x3705, PropType.INTEGER32)
TAG_ATTACH_DATA_BIN = make_tag(0x3701, PropType.BINARY)  # 0x37010102
TAG_IMPORTANCE = make_tag(0x0017, PropType.INTEGER32)  # inline fixed example


# ---------------------------------------------------------------------------
# Fixtures.
# ---------------------------------------------------------------------------


@pytest.fixture()
def simple_msg_bytes() -> bytes:
    """A top-level MSG with subject/sender/to/body/importance, one recip, one attach."""
    root = _Node("Root Entry", is_storage=True)

    # Top-level message properties (8-byte header).
    pbytes, streams = _properties_stream(
        8,
        {
            TAG_SUBJECT: "RE: SWIFT payment".encode("utf-16-le"),
            TAG_SENDER_EMAIL: "alice@example.com".encode("utf-16-le"),
            TAG_DISPLAY_TO: "bob@example.com".encode("utf-16-le"),
            TAG_BODY: "Please review the attached.".encode("utf-16-le"),
            TAG_IMPORTANCE: _u32(2),  # inline fixed (high importance)
        },
    )
    root.add(_Node("__properties_version1.0", is_storage=False, data=pbytes))
    for name, data in streams.items():
        root.add(_Node(name, is_storage=False, data=data))

    # One recipient (24-byte sub header).
    _add_storage_with_props(
        root,
        "__recip_version1.0_#00000000",
        24,
        {
            TAG_RECIP_EMAIL: "bob@example.com".encode("utf-16-le"),
            TAG_RECIP_TYPE: _u32(1),  # To
        },
    )

    # One by-value attachment (24-byte sub header).
    att = _add_storage_with_props(
        root,
        "__attach_version1.0_#00000000",
        24,
        {
            TAG_ATTACH_FNAME: "invoice.pdf".encode("utf-16-le"),
            TAG_ATTACH_METHOD: _u32(1),  # ATTACH_BY_VALUE
            TAG_ATTACH_DATA_BIN: b"%PDF-1.4 fake pdf bytes",
        },
    )
    assert att is not None
    return _make_msg_image(root)


@pytest.fixture()
def embedded_msg_bytes() -> bytes:
    """A top-level MSG whose single attachment is an embedded message (method 5)."""
    root = _Node("Root Entry", is_storage=True)
    pbytes, streams = _properties_stream(
        8, {TAG_SUBJECT: "Outer message".encode("utf-16-le")}
    )
    root.add(_Node("__properties_version1.0", is_storage=False, data=pbytes))
    for name, data in streams.items():
        root.add(_Node(name, is_storage=False, data=data))

    # Attachment storage with an embedded-message sub-storage (3701000D).
    att = root.add(_Node("__attach_version1.0_#00000000", is_storage=True))
    apb, astreams = _properties_stream(24, {TAG_ATTACH_METHOD: _u32(5)})
    att.add(_Node("__properties_version1.0", is_storage=False, data=apb))
    for name, data in astreams.items():
        att.add(_Node(name, is_storage=False, data=data))

    # Embedded message: __substg1.0_3701000D is itself a *storage* (24B header).
    embed = att.add(_Node("__substg1.0_3701000D", is_storage=True))
    epb, estreams = _properties_stream(
        24,
        {
            TAG_SUBJECT: "Inner embedded message".encode("utf-16-le"),
            TAG_BODY: "secret inner body".encode("utf-16-le"),
        },
    )
    embed.add(_Node("__properties_version1.0", is_storage=False, data=epb))
    for name, data in estreams.items():
        embed.add(_Node(name, is_storage=False, data=data))

    return _make_msg_image(root)


# ---------------------------------------------------------------------------
# Tests.
# ---------------------------------------------------------------------------


def test_cfbf_writer_roundtrips_via_olefile(simple_msg_bytes):
    """Sanity: our test CFBF writer is readable by olefile (oracle for the rest)."""
    import io

    ole = olefile.OleFileIO(io.BytesIO(simple_msg_bytes))
    names = ["/".join(e) for e in ole.listdir(streams=True, storages=True)]
    assert "__properties_version1.0" in names
    assert "__substg1.0_0037001F" in names  # full-tag stream naming (H12)
    assert "__recip_version1.0_#00000000" in [e[0] for e in ole.listdir(storages=True)]


def test_open_msg_recovers_envelope(simple_msg_bytes):
    """open_msg recovers subject/sender/to/body from a top-level MSG (§10.1)."""
    msg = open_msg(simple_msg_bytes)
    install_renderer(msg)
    assert isinstance(msg, MapiMessage)
    assert msg.render(TAG_SUBJECT) == "RE: SWIFT payment"
    assert msg.render(TAG_SENDER_EMAIL) == "alice@example.com"
    assert msg.render(TAG_DISPLAY_TO) == "bob@example.com"
    assert msg.render(TAG_BODY) == "Please review the attached."


def test_inline_fixed_value_decoded(simple_msg_bytes):
    """A fixed <=8B type (PidTagImportance) is stored inline in the 16B entry (H12)."""
    msg = open_msg(simple_msg_bytes)
    v = msg.by_id(0x0017)
    assert v is not None
    assert int.from_bytes(v.raw[:4], "little") == 2


def test_full_tag_substg_naming(simple_msg_bytes):
    """Variable props are addressed by the FULL 8-hex tag, not 0x1000+id (H12)."""
    # Subject (0x0037001F) must have produced a value; its raw must be the
    # UTF-16LE source (no transform applied to the tag/name).
    msg = open_msg(simple_msg_bytes)
    v = msg.get_tag(TAG_SUBJECT)
    assert v is not None
    assert v.raw == "RE: SWIFT payment".encode("utf-16-le")


def test_recipient_parsed(simple_msg_bytes):
    """__recip_version1.0_#* -> MapiRecipient with recipient_type populated."""
    msg = open_msg(simple_msg_bytes)
    assert len(msg.recipients) == 1
    r = msg.recipients[0]
    r2 = install_renderer(r)
    assert r.recipient_type == 1  # To
    assert r2.render(0x3003) == "bob@example.com"


def test_attachment_parsed_by_value(simple_msg_bytes):
    """__attach_version1.0_#* -> MapiAttachment; by-value data via open_data."""
    msg = open_msg(simple_msg_bytes)
    assert len(msg.attachments) == 1
    a = msg.attachments[0]
    install_renderer(a)
    assert a.method == 1  # ATTACH_BY_VALUE
    assert a.render(0x3704) == "invoice.pdf"
    assert a.embedded is None
    assert a.open_data is not None
    assert a.open_data().startswith(b"%PDF")


def test_embedded_message_recursion(embedded_msg_bytes):
    """Embedded __substg1.0_3701000D storage recurses into a child MapiMessage."""
    msg = open_msg(embedded_msg_bytes)
    install_renderer(msg)
    assert msg.render(TAG_SUBJECT) == "Outer message"
    assert len(msg.attachments) == 1
    att = msg.attachments[0]
    assert att.method == 5  # ATTACH_EMBEDDED_MSG
    assert att.embedded is not None
    assert len(msg.embedded_messages) == 1
    inner = att.embedded
    install_renderer(inner)
    assert inner.render(TAG_SUBJECT) == "Inner embedded message"
    assert inner.render(TAG_BODY) == "secret inner body"


def test_not_a_msg_raises():
    """Non-CFBF bytes raise NotAMsgError (recovery-first: only 'not a store' raises)."""
    from pstforensic.exceptions import NotAMsgError

    with pytest.raises(NotAMsgError):
        open_msg(b"this is not a compound file at all" * 20)


def test_missing_properties_stream_raises():
    """A CFBF lacking __properties_version1.0 is not an Outlook MSG."""
    from pstforensic.exceptions import NotAMsgError

    root = _Node("Root Entry", is_storage=True)
    root.add(_Node("Some Other Stream", is_storage=False, data=b"xyz"))
    img = _make_msg_image(root)
    with pytest.raises(NotAMsgError):
        open_msg(img)


# --- nameid (named-property map) -------------------------------------------


def test_nameid_id_named_resolution():
    """NAMEID entry with N=0 resolves to (GUID, lid); NPID = 0x8000 + ordinal (H17)."""
    sink = WarningSink()
    # Two id-named entries: one PS_PUBLIC_STRINGS (wGuid=2), one custom GUID@idx0.
    custom_guid = bytes.fromhex("01020304" "0506" "0708" "090a0b0c0d0e0f10")
    guid_stream = custom_guid  # GuidStream[0]
    entry = bytearray()
    # ordinal 0: lid 0x8201, N=0, wGuid=2 (PS_PUBLIC_STRINGS)
    entry += struct.pack("<IHH", 0x8201, 0x0000, 2 << 1)
    # ordinal 1: lid 0x0042, N=0, wGuid=3 (GuidStream[0])
    entry += struct.pack("<IHH", 0x0042, 0x0000, 3 << 1)
    nm = NamedPropMap.from_streams(guid_stream, bytes(entry), b"", sink=sink)
    assert len(nm) == 2
    np0 = nm.resolve(0x8000)
    assert np0 is not None and np0.lid == 0x8201
    assert np0.guid == PS_PUBLIC_STRINGS
    np1 = nm.resolve(0x8001)
    assert np1 is not None and np1.lid == 0x0042
    # GuidStream[0] -> the custom GUID, canonical form.
    assert np1.guid == "04030201-0605-0807-090a-0b0c0d0e0f10"


def test_nameid_string_named_resolution():
    """NAMEID with N=1 reads its name from the String stream at dwStringOffset (H17)."""
    sink = WarningSink()
    name = "x-custom-header"
    nb = name.encode("utf-16-le")
    string_stream = struct.pack("<I", len(nb)) + nb
    # N=1 (bit0 set), wGuid=1 (PS_MAPI), dwStringOffset=0
    entry = struct.pack("<IHH", 0, 0x0001 | (1 << 1), 0)
    nm = NamedPropMap.from_streams(b"", entry, string_stream, sink=sink)
    np = nm.resolve(0x8000)
    assert np is not None and np.is_string
    assert np.name == name
    assert nm.label(0x8000) == name


def test_nameid_missing_is_non_fatal():
    """No entry stream -> empty map + NAMEID_MISSING warning, never raises (AC-5)."""
    sink = WarningSink()
    nm = NamedPropMap.from_streams(None, None, None, sink=sink)
    assert len(nm) == 0
    assert WarnCode.NAMEID_MISSING in sink.codes()
    assert nm.resolve(0x8000) is None


def test_msg_with_nameid_storage():
    """A full MSG carrying a __nameid_version1.0 storage resolves named props."""
    root = _Node("Root Entry", is_storage=True)
    pbytes, streams = _properties_stream(
        8, {TAG_SUBJECT: "Named".encode("utf-16-le")}
    )
    root.add(_Node("__properties_version1.0", is_storage=False, data=pbytes))
    for nm_name, data in streams.items():
        root.add(_Node(nm_name, is_storage=False, data=data))

    nid = root.add(_Node("__nameid_version1.0", is_storage=True))
    # Its own (empty) properties stream + the three nameid streams.
    npb, _ = _properties_stream(24, {})
    nid.add(_Node("__properties_version1.0", is_storage=False, data=npb))
    name = "x-spam-score"
    nb = name.encode("utf-16-le")
    nid.add(_Node("__substg1.0_00020102", is_storage=False, data=b""))
    nid.add(
        _Node(
            "__substg1.0_00030102",
            is_storage=False,
            data=struct.pack("<IHH", 0, 0x0001 | (1 << 1), 0),
        )
    )
    nid.add(
        _Node(
            "__substg1.0_00040102",
            is_storage=False,
            data=struct.pack("<I", len(nb)) + nb,
        )
    )

    img = _make_msg_image(root)
    msg = open_msg(img)
    nm = msg.nameid  # set by the parser
    assert isinstance(nm, NamedPropMap)
    assert nm.label(0x8000) == name
