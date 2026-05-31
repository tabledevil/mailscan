"""LTP-layer tests — heap (HN), BTH, PC, TC ([MS-PST] §2.3).

Governing rule (PLAN §0.5): every byte-level constant is locked by a
known-answer fixture.  The synth NDB writer (``synth._PstBuilder``) gives us a
byte-accurate store whose node *data streams* are caller-supplied raw bytes, so
we hand-assemble spec-correct HN/PC/TC payloads, push them through the real NDB
reader (``NodeDatabase``), and assert the LTP layer round-trips the known
property/row set.

Spec citations are inline.  Each ``# [MS-PST] §x.y`` comment marks the constant
that test pins.
"""
from __future__ import annotations

import struct

from pstforensic.exceptions import WarnCode, WarningSink
from pstforensic.fileio import FileReader
from pstforensic.ndb.bref import make_nid, NID_TYPE_NORMAL_MESSAGE
from pstforensic.ndb.nodedb import NodeDatabase
from pstforensic.proptypes import make_tag, PropType
from pstforensic.variant import UNICODE, CRYPT_NONE

from pstforensic.ltp import (
    BTreeOnHeap,
    HeapOnNode,
    PropertyContext,
    TableContext,
    resolve_hid,
)
from pstforensic.ltp.heap import HN_CLIENT_BTH, HN_CLIENT_PC, HN_CLIENT_TC
from pstforensic.tests import synth


# ---------------------------------------------------------------------------
# Low-level HN/BTH/PC/TC byte assemblers (the fixtures)
# ---------------------------------------------------------------------------
def _make_hid(index_1based: int, block_index: int = 0) -> int:
    """Compose a HID: hidType=0, hidIndex(1-based), hidBlockIndex ([MS-PST] §2.2.2.1)."""
    return (0) | ((index_1based & 0x7FF) << 5) | ((block_index & 0xFFFF) << 16)


def _build_heap(client_sig: int, hid_user_root: int,
                allocations: list[bytes]) -> bytes:
    """Assemble a single-block Heap-on-Node ([MS-PST] §2.3.1).

    Layout: HNHDR(12) | alloc[0] | alloc[1] | ... | HNPAGEMAP.
    ``allocations`` are placed in order; allocation ``i+1`` (1-based hidIndex)
    is the i-th entry here (HNHDR occupies allocation slot but is NOT in the
    pagemap — actually the HNHDR is allocation 0 conceptually; we place real
    user allocations starting right after the 12-byte header and index them
    1-based so hidIndex 1 → first user allocation).
    """
    # Body begins after the 12-byte HNHDR.
    body = bytearray()
    offsets = [12]  # rgibAlloc[0] = start of first allocation (after HNHDR)
    for a in allocations:
        body += a
        offsets.append(offsets[-1] + len(a))
    ib_hnpm = 12 + len(body)

    hdr = struct.pack("<HBBI I", ib_hnpm, 0xEC, client_sig, hid_user_root, 0)
    # HNPAGEMAP: cAlloc, cFree, rgibAlloc[cAlloc+1] ([MS-PST] §2.3.1.5).
    c_alloc = len(allocations)
    pagemap = struct.pack("<HH", c_alloc, 0)
    for o in offsets:
        pagemap += struct.pack("<H", o)
    return bytes(hdr) + bytes(body) + pagemap


def _build_bth_leaf(cb_key: int, cb_ent: int,
                    records: list[tuple[bytes, bytes]],
                    leaf_hid_index: int = 2) -> tuple[bytes, bytes]:
    """Build a flat (single-leaf) BTH: returns (header_alloc, leaf_alloc).

    BTHHEADER(8): bType=0xB5, cbKey, cbEnt, bIdxLevels=0, hidRoot ([MS-PST] §2.3.2.1).
    hidRoot must point at the leaf's actual heap hidIndex; the caller passes
    ``leaf_hid_index`` (default 2, i.e. header@1/leaf@2).
    """
    leaf = bytearray()
    for k, v in records:
        assert len(k) == cb_key and len(v) == cb_ent
        leaf += k + v
    hid_leaf = _make_hid(leaf_hid_index)
    header = struct.pack("<BBBBI", 0xB5, cb_key, cb_ent, 0, hid_leaf)
    return header, bytes(leaf)


def _build_pc(properties: dict[int, bytes]) -> bytes:
    """Build a PC heap with inline + heap-HID properties ([MS-PST] §2.3.3).

    ``properties`` maps full tag → value bytes.  Fixed ≤4B types are stored
    inline (in dwValueHnid); everything else gets its own heap allocation and
    is referenced by HID.  Allocation plan (hidIndex 1-based):
      1: BTHHEADER, 2: BTH leaf, 3..: variable/large value allocations.
    """
    from pstforensic.proptypes import is_inline_in_pc, split_tag

    var_allocs: list[bytes] = []
    records: list[tuple[bytes, bytes]] = []
    next_index = 3
    for tag in sorted(properties):
        _pid, ptype = split_tag(tag)
        value = properties[tag]
        if is_inline_in_pc(ptype):
            dw = (value + b"\x00\x00\x00\x00")[:4]
            hnid = struct.unpack("<I", dw)[0]
        else:
            var_allocs.append(value)
            hnid = _make_hid(next_index)
            next_index += 1
        prop_id = (tag >> 16) & 0xFFFF
        key = struct.pack("<H", prop_id)
        ent = struct.pack("<HI", ptype, hnid)
        records.append((key, ent))

    header, leaf = _build_bth_leaf(2, 6, records)
    allocations = [header, leaf] + var_allocs
    hid_user_root = _make_hid(1)
    return _build_heap(HN_CLIENT_PC, hid_user_root, allocations)


def _open_node_with_data(payload: bytes, *, subnodes: dict | None = None,
                         sink: WarningSink | None = None):
    """Build a 1-node PST whose node.data_stream() == ``payload`` and open it.

    Returns ``(noderef, sink)``.  Uses ``synth._PstBuilder`` directly so the HN
    payload is the literal data block (the high-level ``build_unicode_pst`` wraps
    payloads in an envelope blob, which we don't want here).
    """
    b = synth._PstBuilder(UNICODE, CRYPT_NONE)
    bid_sub = 0
    if subnodes:
        sl = []
        for local_nid, sub_payload in subnodes.items():
            sb = b.add_data_block(sub_payload)
            sl.append((local_nid, sb, 0))
        bid_sub = b.add_slblock(sl)
    bid_data = b.add_data_block(payload)
    nid = make_nid(NID_TYPE_NORMAL_MESSAGE, 1)
    b.add_node(nid, bid_data, bid_sub)
    image = b.build()
    sk = sink if sink is not None else WarningSink()
    db = NodeDatabase.open(FileReader(image, sink=sk), sink=sk)
    return db.node(nid), sk


# ---------------------------------------------------------------------------
# HID resolution ([MS-PST] §2.2.2.1 / Appendix A H2)
# ---------------------------------------------------------------------------
def test_hid_fields_and_one_based():
    # hidType bits0-4, hidIndex bits5-15 (1-based), hidBlockIndex bits16-31.
    hid = _make_hid(3, block_index=2)
    h = resolve_hid(hid)
    assert h.hid_type == 0
    assert h.hid_index == 3
    assert h.block_index == 2
    assert h.is_hid is True


def test_hid_index_zero_rejected():
    # Appendix A H2: hidIndex MUST NOT be 0 (1-based). A hidType==0,index==0 HID
    # must NOT resolve to a real allocation — it warns and yields b"".
    payload = _build_pc({make_tag(0x3001, PropType.STRING): "X".encode("utf-16-le")})
    noderef, _ = _open_node_with_data(payload)
    heap = HeapOnNode(noderef, UNICODE)
    sink = heap.sink
    # A genuinely malformed HID: hidType 0, hidIndex 0, but a NON-null value
    # (blockIndex set) so it is not the all-zero NULL HID — this must warn and
    # yield b"". (The all-zero value 0x0 is the legitimate NULL HID and is
    # silently empty, per [MS-PST] §2.3.3.2.)
    assert heap.get_allocation(_make_hid(0, block_index=1)) == b""  # index 0
    assert WarnCode.ENTRY_OVERFLOW in sink.codes()


def test_hid_subnode_nid_not_hid():
    # A HNID whose hidType != 0 is a subnode NID, not a heap HID (Appendix A H6).
    h = resolve_hid(0x21)  # nidType bits set
    assert h.is_hid is False


# ---------------------------------------------------------------------------
# Heap-on-Node ([MS-PST] §2.3.1)
# ---------------------------------------------------------------------------
def test_heap_header_and_allocations():
    # HNHDR bSig=0xEC, bClientSig, hidUserRoot; HNPAGEMAP rgibAlloc extents.
    allocs = [b"AAAA", b"BBBBBB", b"C"]
    heap_bytes = _build_heap(HN_CLIENT_BTH, _make_hid(1), allocs)
    noderef, _ = _open_node_with_data(heap_bytes)
    heap = HeapOnNode(noderef, UNICODE)
    assert heap.client_sig == HN_CLIENT_BTH  # 0xB5
    assert heap.get_allocation(_make_hid(1)) == b"AAAA"
    assert heap.get_allocation(_make_hid(2)) == b"BBBBBB"
    assert heap.get_allocation(_make_hid(3)) == b"C"


def test_heap_bad_sig_warns():
    allocs = [b"ZZZZ"]
    heap_bytes = bytearray(_build_heap(HN_CLIENT_PC, _make_hid(1), allocs))
    heap_bytes[2] = 0x00  # corrupt bSig (was 0xEC)
    noderef, _ = _open_node_with_data(bytes(heap_bytes))
    heap = HeapOnNode(noderef, UNICODE)
    assert WarnCode.SIG_MISMATCH in heap.sink.codes()


# ---------------------------------------------------------------------------
# BTree-on-Heap ([MS-PST] §2.3.2)
# ---------------------------------------------------------------------------
def test_bth_leaf_records_roundtrip():
    recs = [(struct.pack("<H", k), struct.pack("<HI", k, k * 10))
            for k in (1, 5, 9)]
    header, leaf = _build_bth_leaf(2, 6, recs)
    heap_bytes = _build_heap(HN_CLIENT_BTH, _make_hid(1), [header, leaf])
    noderef, _ = _open_node_with_data(heap_bytes)
    heap = HeapOnNode(noderef, UNICODE)
    bth = BTreeOnHeap.from_heap(heap)
    assert bth.header.b_type == 0xB5
    assert bth.header.cb_key == 2 and bth.header.cb_ent == 6
    out = list(bth.records())
    assert [k for k, _ in out] == [struct.pack("<H", k) for k in (1, 5, 9)]


def test_bth_out_of_order_linear_scan():
    # Out-of-order keys → warn + linear scan still yields all records (§0.5).
    recs = [(struct.pack("<H", k), struct.pack("<HI", k, 0)) for k in (9, 1, 5)]
    header, leaf = _build_bth_leaf(2, 6, recs)
    heap_bytes = _build_heap(HN_CLIENT_BTH, _make_hid(1), [header, leaf])
    noderef, _ = _open_node_with_data(heap_bytes)
    heap = HeapOnNode(noderef, UNICODE)
    bth = BTreeOnHeap.from_heap(heap)
    keys = [struct.unpack("<H", k)[0] for k, _ in bth.records()]
    assert sorted(keys) == [1, 5, 9]
    assert WarnCode.SIG_MISMATCH in heap.sink.codes()


# ---------------------------------------------------------------------------
# Property Context ([MS-PST] §2.3.3 / Appendix A H5/H6)
# ---------------------------------------------------------------------------
def test_pc_inline_and_heap_values():
    subject = "Re: SWIFT payment"
    tag_subject = make_tag(0x0037, PropType.STRING)        # variable → HID
    tag_int = make_tag(0x0E08, PropType.INTEGER32)         # ≤4B → inline (H5)
    tag_bool = make_tag(0x0E1F, PropType.BOOLEAN)          # 1B → inline
    tag_i64 = make_tag(0x3008, PropType.INTEGER64)         # 8B → HID (H5)
    props = {
        tag_subject: subject.encode("utf-16-le"),
        tag_int: struct.pack("<i", 123456),
        tag_bool: struct.pack("<H", 1),
        tag_i64: struct.pack("<q", 0x1122334455667788),
    }
    payload = _build_pc(props)
    noderef, sink = _open_node_with_data(payload)
    obj = PropertyContext.from_node(noderef, UNICODE, sink=sink)

    assert obj.get_tag(tag_subject).raw.decode("utf-16-le") == subject
    assert struct.unpack("<i", obj.get_tag(tag_int).raw[:4])[0] == 123456
    assert obj.get_tag(tag_bool).raw[:1] == b"\x01"
    assert struct.unpack("<q", obj.get_tag(tag_i64).raw[:8])[0] == 0x1122334455667788


def test_pc_message_store_displayname():
    # Model the message-store PC: PidTagDisplayName (0x3001001F).
    tag_dn = make_tag(0x3001, PropType.STRING)
    name = "Personal Folders"
    payload = _build_pc({tag_dn: name.encode("utf-16-le")})
    noderef, sink = _open_node_with_data(payload)
    obj = PropertyContext.from_node(noderef, UNICODE, sink=sink)
    assert obj.get_tag(tag_dn).raw.decode("utf-16-le") == name


def test_pc_mv_string_split():
    # MV variable (0x101F): ulCount + (count+1) offset table + blocks (§2.3.3.4).
    tag_mv = make_tag(0x1234, PropType.MV_STRING)
    items = ["alpha", "beta", "gamma"]
    enc = [s.encode("utf-16-le") for s in items]
    # offset table is relative to the start of the MV blob.
    count = len(enc)
    header_len = 4 + (count + 1) * 4
    offsets = [header_len]
    for e in enc:
        offsets.append(offsets[-1] + len(e))
    blob = struct.pack("<I", count)
    for o in offsets:
        blob += struct.pack("<I", o)
    blob += b"".join(enc)
    payload = _build_pc({tag_mv: blob})
    noderef, sink = _open_node_with_data(payload)
    obj = PropertyContext.from_node(noderef, UNICODE, sink=sink)
    mv = obj.get_tag(tag_mv)
    assert mv.elements is not None
    assert [e.decode("utf-16-le") for e in mv.elements] == items


def test_pc_mv_integer32_split():
    # Fixed-width MV (0x1003): ulCount + N×4B items (§2.3.3.4).
    tag_mv = make_tag(0x4321, PropType.MV_INTEGER32)
    vals = [10, 20, 30, 40]
    blob = struct.pack("<I", len(vals)) + b"".join(struct.pack("<i", v) for v in vals)
    payload = _build_pc({tag_mv: blob})
    noderef, sink = _open_node_with_data(payload)
    obj = PropertyContext.from_node(noderef, UNICODE, sink=sink)
    mv = obj.get_tag(tag_mv)
    assert [struct.unpack("<i", e)[0] for e in mv.elements] == vals


def test_pc_large_value_via_subnode():
    # >3580B variable value: dwValueHnid is a subnode NID, not a heap HID (H6).
    tag_body = make_tag(0x1000, PropType.STRING)  # PidTagBody
    big = ("x" * 4000).encode("utf-16-le")
    # Subnode NID: the disambiguating nidType is the LOW 5 bits and MUST be
    # non-zero, else the HNID is read as an HID ([MS-PST] §2.3.3.2). 0x4D has
    # nidType 0x0D.
    sub_nid = 0x4D
    # Build a PC whose record references the subnode NID directly.
    prop_id = 0x1000
    records = [(struct.pack("<H", prop_id),
                struct.pack("<HI", int(PropType.STRING), sub_nid))]
    header, leaf = _build_bth_leaf(2, 6, records)
    payload = _build_heap(HN_CLIENT_PC, _make_hid(1), [header, leaf])
    noderef, sink = _open_node_with_data(payload, subnodes={sub_nid: big})
    obj = PropertyContext.from_node(noderef, UNICODE, sink=sink)
    assert obj.get_tag(tag_body).raw == big


# ---------------------------------------------------------------------------
# Table Context ([MS-PST] §2.3.4 / Appendix A H23)
# ---------------------------------------------------------------------------
def _build_tc(columns, rows, *, with_row_index=True):
    """Build a TC heap whose Row Matrix lives in a subnode.

    ``columns`` = list of (tag, cb_data) for variable/inline cells; the dwRowID
    column (PidTagLtpRowId 0x67480003, ibData=0, 4B) is added implicitly.
    ``rows`` = list of (row_id, {tag: value_or_None}) where None ⇒ absent cell.

    Returns ``(heap_bytes, {subnode_nid: matrix_bytes})``.
    """
    from pstforensic.ltp.tc import PID_LTP_ROW_ID

    # Column plan: dwRowID(4B @0), then each declared column.  We place all
    # declared cells in the "4-byte" group for simplicity (each 4B HNID/inline).
    cols = [(PID_LTP_ROW_ID, 4)] + list(columns)
    # Assign ibData sequentially in the 4-byte group.
    col_descs = []
    ib = 0
    for i, (tag, cb) in enumerate(cols):
        col_descs.append((tag, ib, cb, i))  # iBit = column index
        ib += cb
    end_4b = ib
    # No 2B/1B groups; CEB follows immediately.
    n_cols = len(cols)
    ceb_bytes = (n_cols + 7) // 8
    rgib = (end_4b, end_4b, end_4b, end_4b + ceb_bytes)
    row_size = end_4b + ceb_bytes

    # Heap allocations: 1=TCINFO, then (if present) 2=RowIndex BTH header,
    # 3=RowIndex leaf, then variable-cell value allocations.  Without a
    # RowIndex the value allocations start right after TCINFO at hidIndex 2.
    var_allocs: list[bytes] = []
    next_index = 4 if with_row_index else 2

    matrix = bytearray()
    row_index_records = []
    for row_idx, (row_id, cells) in enumerate(rows):
        row = bytearray(row_size)
        struct.pack_into("<I", row, 0, row_id)  # dwRowID @ ibData 0
        ceb = bytearray(ceb_bytes)
        # dwRowID column always present (col 0).
        ceb[0] |= 0x80
        for tag, ib_data, cb, i_bit in col_descs:
            if tag == PID_LTP_ROW_ID:
                continue
            val = cells.get(tag, None)
            if val is None:
                continue  # absent → CEB bit stays 0
            ceb[i_bit // 8] |= (0x80 >> (i_bit % 8))
            from pstforensic.proptypes import is_inline_in_pc, split_tag
            _pid, ptype = split_tag(tag)
            if is_inline_in_pc(ptype):
                cell = (val + b"\x00\x00\x00\x00")[:cb]
            else:
                var_allocs.append(val)
                hid = _make_hid(next_index)
                next_index += 1
                cell = struct.pack("<I", hid)
            row[ib_data:ib_data + cb] = cell
        # write CEB
        row[rgib[2]:rgib[2] + ceb_bytes] = ceb
        matrix += row
        row_index_records.append(
            (struct.pack("<I", row_id), struct.pack("<I", row_idx)))

    # The Row Matrix lives in a subnode (hnidRows = subnode NID — Appendix A H23).
    # The nidType (low 5 bits) MUST be non-zero or the HNID reads as an HID
    # ([MS-PST] §2.3.3.2); 0x8D has nidType 0x0D.
    matrix_nid = 0x8D
    hnid_rows = matrix_nid

    if with_row_index:
        # RowIndex BTH: header@hidIndex 2, leaf@hidIndex 3 (after TCINFO@1).
        ri_header, ri_leaf = _build_bth_leaf(4, 4, row_index_records,
                                             leaf_hid_index=3)
        hid_row_index = _make_hid(2)
        allocs_head = [None, ri_header, ri_leaf]  # placeholder for TCINFO @1
    else:
        hid_row_index = 0
        allocs_head = [None]

    # TCINFO (@ hidIndex 1).
    tcinfo = struct.pack("<BB", 0x7C, n_cols)
    tcinfo += struct.pack("<HHHH", *rgib)
    tcinfo += struct.pack("<III", hid_row_index, hnid_rows, 0)  # hidIndex=0
    for tag, ib_data, cb, i_bit in col_descs:
        tcinfo += struct.pack("<IHBB", tag, ib_data, cb, i_bit)

    allocs_head[0] = tcinfo
    allocations = allocs_head + var_allocs
    heap_bytes = _build_heap(HN_CLIENT_TC, _make_hid(1), allocations)
    return heap_bytes, {matrix_nid: bytes(matrix)}


def test_tc_rows_roundtrip_via_rowindex():
    # Contents-table style TC: subject column per row, mapped by dwRowID (H23).
    tag_subject = make_tag(0x0037, PropType.STRING)
    rows = [
        (0x0A, {tag_subject: "First".encode("utf-16-le")}),
        (0x0B, {tag_subject: "Second".encode("utf-16-le")}),
        (0x0C, {tag_subject: "Third".encode("utf-16-le")}),
    ]
    heap_bytes, subs = _build_tc([(tag_subject, 4)], rows)
    noderef, sink = _open_node_with_data(heap_bytes, subnodes=subs)
    out = list(TableContext.from_node(noderef, UNICODE, sink=sink))
    subjects = [o.get_tag(tag_subject).raw.decode("utf-16-le") for o in out]
    assert subjects == ["First", "Second", "Third"]


def test_tc_ceb_null_cell_omitted():
    # CEB: a row missing the subject cell must NOT carry that property (§2.3.4.4.1).
    tag_subject = make_tag(0x0037, PropType.STRING)
    tag_flags = make_tag(0x0E07, PropType.INTEGER32)  # inline cell
    rows = [
        (0x01, {tag_subject: "Has".encode("utf-16-le"),
                tag_flags: struct.pack("<i", 1)}),
        (0x02, {tag_subject: None,                     # absent → null
                tag_flags: struct.pack("<i", 2)}),
    ]
    heap_bytes, subs = _build_tc([(tag_subject, 4), (tag_flags, 4)], rows)
    noderef, sink = _open_node_with_data(heap_bytes, subnodes=subs)
    out = list(TableContext.from_node(noderef, UNICODE, sink=sink))
    by_id = {struct.unpack("<I", o.get_tag(make_tag(0x6748, PropType.INTEGER32)).raw[:4])[0]: o
             for o in out}
    assert by_id[0x01].get_tag(tag_subject) is not None
    assert by_id[0x02].get_tag(tag_subject) is None  # CEB null → omitted
    # The present integer cell still round-trips on the null-subject row.
    assert struct.unpack("<i", by_id[0x02].get_tag(tag_flags).raw[:4])[0] == 2


def test_tc_rowindex_maps_by_id_not_order():
    # RowIndex maps dwRowID→dwRowIndex; iteration order follows dwRowIndex, not
    # the order row_ids appear (Appendix A H23).  Here row_ids are scrambled but
    # the matrix order (dwRowIndex) is 0,1,2 → output follows the matrix.
    tag_subject = make_tag(0x0037, PropType.STRING)
    rows = [
        (0x33, {tag_subject: "idx0".encode("utf-16-le")}),
        (0x11, {tag_subject: "idx1".encode("utf-16-le")}),
        (0x22, {tag_subject: "idx2".encode("utf-16-le")}),
    ]
    heap_bytes, subs = _build_tc([(tag_subject, 4)], rows)
    noderef, sink = _open_node_with_data(heap_bytes, subnodes=subs)
    out = list(TableContext.from_node(noderef, UNICODE, sink=sink))
    # dwRowIndex order 0,1,2 → idx0, idx1, idx2 regardless of row_id values.
    assert [o.get_tag(tag_subject).raw.decode("utf-16-le") for o in out] == \
        ["idx0", "idx1", "idx2"]


def test_tc_no_rowindex_linear_scan():
    # hidRowIndex==0 → linear scan recovery path still yields rows (§2.3.4 / §0.5).
    tag_subject = make_tag(0x0037, PropType.STRING)
    rows = [
        (0x01, {tag_subject: "A".encode("utf-16-le")}),
        (0x02, {tag_subject: "B".encode("utf-16-le")}),
    ]
    heap_bytes, subs = _build_tc([(tag_subject, 4)], rows, with_row_index=False)
    noderef, sink = _open_node_with_data(heap_bytes, subnodes=subs)
    out = list(TableContext.from_node(noderef, UNICODE, sink=sink))
    assert [o.get_tag(tag_subject).raw.decode("utf-16-le") for o in out] == ["A", "B"]
    assert WarnCode.SIG_MISMATCH in sink.codes()
