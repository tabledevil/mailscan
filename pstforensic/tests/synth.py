"""Byte-accurate synthetic PST/OST/MSG writer — the shared test oracle.

This module is the linchpin of the whole project: it writes **minimal but
byte-accurate** PST/OST stores (and CFBF MSG files) so every higher layer
(LTP, messaging, recovery) can round-trip against a *known* item set instead of
needing a proprietary Outlook sample.  All trailers, signatures and CRCs are
computed with the real :mod:`pstforensic.ndb.crc` primitives and the layout
follows the spec-verified geometry in :mod:`pstforensic.variant` (PLAN
Appendix A).

Public builders (CONTRACTS §"Test fixtures"):
  * ``build_unicode_pst(*, messages, crypt=CRYPT_NONE, folders=None) -> bytes``
  * ``build_ansi_pst(*, messages, crypt=CRYPT_NONE) -> bytes``
  * ``build_msg(*, props, recipients=(), attachments=()) -> bytes``

``messages`` is a list of dicts shaped like::

    {"subject": str, "sender": str, "to": str, "body": str,
     "props": {tag:int -> value:bytes}}

The PST builders here intentionally produce a *structurally* valid NDB (header,
ROOT, single BBT page, single NBT page, data/XBLOCK blocks, subnode trees) — the
node *payloads* are caller-supplied raw bytes.  This lets the NDB round-trip
tests assert exact byte equality, while the LTP tier layers real HN/PC/TC
payloads on top using the same node ids.

Corruption knobs (used by the recovery tier) are exposed via ``corrupt=`` on the
PST builders: ``"truncate"``, ``"bad_header_crc"``, ``"zero_amap"``,
``"drop_nbt_entry"``.

[MS-PST] section citations are inline at each struct.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Iterable, Optional

from ..ndb.bref import (
    BID_INTERNAL_BIT,
    make_nid,
    NID_TYPE_NORMAL_MESSAGE,
)
from ..ndb.block import block_disk_size
from ..ndb.crc import compute_crc, compute_sig
from ..ndb.crypt import encode_block
from ..variant import (
    ANSI,
    CRYPT_NONE,
    UNICODE,
    Variant,
)

# Page-trailer ptypes ([MS-PST] §2.2.2.7.1).
PTYPE_BBT = 0x80
PTYPE_NBT = 0x81

WMAGIC_CLIENT = 0x4D53  # "SM" little-endian
WVER_UNICODE = 23
WVER_ANSI = 14
WVER_CLIENT = 19


# ---------------------------------------------------------------------------
# Low-level block / page emitters
# ---------------------------------------------------------------------------
@dataclass
class _Block:
    """A pending block: its (already-encoded) payload and assigned bid/ib."""

    bid: int                 # full bid (internal bit set for XBLOCK)
    payload: bytes           # cb bytes as they sit on disk (post-encode)
    internal: bool
    ib: int = 0              # filled at layout time


def _block_trailer(cb: int, ib: int, bid: int, payload: bytes,
                   variant: Variant) -> bytes:
    """Emit a BLOCKTRAILER ([MS-PST] §2.2.2.8.1).

    Unicode: cb(2) wSig(2) dwCRC(4) bid(8)
    ANSI:    cb(2) wSig(2) bid(4)  dwCRC(4)
    CRC is over the ``cb`` payload bytes only (excludes padding).
    """
    w_sig = compute_sig(ib, bid)
    dw_crc = compute_crc(payload[:cb])
    if variant.is_unicode:
        return struct.pack("<HHI Q", cb, w_sig, dw_crc, bid)
    return struct.pack("<HH II", cb, w_sig, bid & 0xFFFFFFFF, dw_crc)


def _emit_block(blk: _Block, variant: Variant) -> bytes:
    """Pad ``blk.payload`` to disk size and append the BLOCKTRAILER."""
    cb = len(blk.payload)
    disk = block_disk_size(cb, variant)
    pad_len = disk - variant.block_trailer_size - cb
    body = blk.payload + b"\x00" * pad_len
    return body + _block_trailer(cb, blk.ib, blk.bid, blk.payload, variant)


def _page_trailer(ptype: int, ib: int, bid: int, page_wo_trailer: bytes,
                  variant: Variant) -> bytes:
    """Emit a PAGETRAILER ([MS-PST] §2.2.2.7.1).

    Unicode: ptype(1) ptypeRepeat(1) wSig(2) dwCRC(4) bid(8)
    ANSI:    ptype(1) ptypeRepeat(1) wSig(2) bid(4)  dwCRC(4)
    CRC is over the page bytes preceding the trailer.
    """
    w_sig = compute_sig(ib, bid)
    dw_crc = compute_crc(page_wo_trailer)
    if variant.is_unicode:
        return struct.pack("<BBHI Q", ptype, ptype, w_sig, dw_crc, bid)
    return struct.pack("<BBH II", ptype, ptype, w_sig, bid & 0xFFFFFFFF, dw_crc)


def _bref_bytes(bid: int, ib: int, variant: Variant) -> bytes:
    """Serialize a BREF (BID then IB) ([MS-PST] §2.2.2.4)."""
    w = variant.bid_size
    return bid.to_bytes(w, "little") + ib.to_bytes(w, "little")


# ---------------------------------------------------------------------------
# The store builder
# ---------------------------------------------------------------------------
class _PstBuilder:
    """Assembles a structurally-valid single-level NBT/BBT PST image.

    Layout (in file order):
        [0]                 HEADER (page_size-aligned region)
        [header end ...]    data + internal blocks (64B aligned each)
        [...]               one BBT page, one NBT page (page_size each)
    All offsets are computed so block/page trailers verify.
    """

    def __init__(self, variant: Variant, crypt: int):
        self.v = variant
        self.crypt = crypt
        self.blocks: list[_Block] = []
        self.nbt_entries: list[tuple[int, int, int, int]] = []  # nid,bidData,bidSub,nidParent
        self._next_block_bid = 4   # data block bids: 4, 8, 12 ... (i bit clear)
        self._next_internal_bid = 4 | BID_INTERNAL_BIT
        self._next_page_bid = 1    # page bids use a separate counter (H22)

    # -- block allocation ------------------------------------------------
    def add_data_block(self, plaintext: bytes) -> int:
        """Add a leaf data block (auto-encoded per crypt); return its bid."""
        bid = self._next_block_bid
        self._next_block_bid += 4
        enc = encode_block(plaintext, self.crypt, bid)
        self.blocks.append(_Block(bid=bid, payload=enc, internal=False))
        return bid

    def add_internal_block(self, payload: bytes) -> int:
        """Add an internal block (XBLOCK/SLBLOCK — never encoded); return its bid."""
        bid = self._next_internal_bid
        self._next_internal_bid += 4
        self.blocks.append(_Block(bid=bid, payload=payload, internal=True))
        return bid

    def add_xblock(self, child_bids: list[int], lcb_total: int) -> int:
        """Build an XBLOCK (btype 0x01, cLevel 1) over data ``child_bids``.

        [MS-PST] §2.2.2.8.3.2: btype(1) cLevel(1) cEnt(2) lcbTotal(4) rgbid[].
        """
        w = self.v.bid_size
        body = struct.pack("<BBHI", 0x01, 1, len(child_bids), lcb_total)
        for cbid in child_bids:
            body += cbid.to_bytes(w, "little")
        return self.add_internal_block(body)

    def add_slblock(self, entries: list[tuple[int, int, int]]) -> int:
        """Build an SLBLOCK leaf (btype 0x02, cLevel 0) ([MS-PST] §2.2.2.8.3.3.1).

        Each entry is ``(local_nid, bidData, bidSub)``.
        Layout: btype(1) cLevel(1) cEnt(2) [dwPadding(4) Unicode] rgentries[].
        """
        w = self.v.bid_size
        body = struct.pack("<BBH", 0x02, 0, len(entries))
        if self.v.is_unicode:
            body += b"\x00\x00\x00\x00"  # dwPadding
        for nid, bdata, bsub in entries:
            body += (nid.to_bytes(w, "little")
                     + bdata.to_bytes(w, "little")
                     + bsub.to_bytes(w, "little"))
        return self.add_internal_block(body)

    # -- node registration ----------------------------------------------
    def add_node(self, nid: int, bid_data: int, bid_sub: int = 0,
                 nid_parent: int = 0) -> None:
        """Register an NBT leaf entry ([MS-PST] §2.2.2.7.7.4)."""
        self.nbt_entries.append((nid, bid_data, bid_sub, nid_parent))

    # -- layout & serialization -----------------------------------------
    def _layout_blocks(self, start: int) -> int:
        """Assign each block an ib starting at ``start``; return next free ib."""
        ib = start
        for blk in self.blocks:
            blk.ib = ib
            ib += block_disk_size(len(blk.payload), self.v)
        return ib

    def _emit_bbt_page(self, ib: int) -> bytes:
        """Emit one BBT page listing every block as a BBTENTRY.

        [MS-PST] §2.2.2.7.7.3 BBTENTRY = BREF + cb(2) + cRef(2) [+pad].
        Unicode cbEnt=24, ANSI cbEnt=12.
        """
        v = self.v
        cb_ent = 24 if v.is_unicode else 12
        ents = b""
        for blk in self.blocks:
            cb = len(blk.payload)
            ent = _bref_bytes(blk.bid, blk.ib, v)
            ent += struct.pack("<HH", cb, 1)  # cb, cRef
            if v.is_unicode:
                ent += b"\x00\x00\x00\x00"     # dwPadding to 24
            ents += ent
        return self._wrap_btpage(ents, len(self.blocks), cb_ent, 0,
                                 PTYPE_BBT, ib)

    def _emit_nbt_page(self, ib: int) -> bytes:
        """Emit one NBT page listing every node as an NBTENTRY.

        [MS-PST] §2.2.2.7.7.4.  Unicode cbEnt=32, ANSI cbEnt=16.
        """
        v = self.v
        cb_ent = 32 if v.is_unicode else 16
        ents = b""
        for nid, bdata, bsub, nparent in self.nbt_entries:
            if v.is_unicode:
                ents += struct.pack("<Q QQ I I",
                                    nid & 0xFFFFFFFF, bdata, bsub,
                                    nparent & 0xFFFFFFFF, 0)
            else:
                ents += struct.pack("<I I I I",
                                    nid & 0xFFFFFFFF, bdata & 0xFFFFFFFF,
                                    bsub & 0xFFFFFFFF, nparent & 0xFFFFFFFF)
        return self._wrap_btpage(ents, len(self.nbt_entries), cb_ent, 0,
                                 PTYPE_NBT, ib)

    def _wrap_btpage(self, ents: bytes, c_ent: int, cb_ent: int, c_level: int,
                     ptype: int, ib: int) -> bytes:
        """Pad entries, append counters + (Unicode) dwPadding + PAGETRAILER."""
        v = self.v
        bid = self._next_page_bid
        self._next_page_bid += 1
        pad_region = (v.page_size - v.page_trailer_size
                      - (4 if v.is_unicode else 0) - 4)
        body = ents + b"\x00" * (pad_region - len(ents))
        c_ent_max = pad_region // cb_ent
        body += struct.pack("<BBBB", c_ent, c_ent_max, cb_ent, c_level)
        if v.is_unicode:
            body += b"\x00\x00\x00\x00"  # dwPadding
        trailer = _page_trailer(ptype, ib, bid, body, v)
        return body + trailer, bid

    def _header_region(self) -> int:
        """Bytes reserved for the HEADER, rounded up to a page boundary.

        The Unicode header extends to dwCRCFull@0x20C (+4) — past a 512-byte
        page — so reserve enough pages to hold the whole header struct and keep
        the first block page-aligned.
        """
        v = self.v
        header_end = (0x0210 if v.is_unicode else 0x0200)
        pages = (max(v.page_size, header_end) + v.page_size - 1) // v.page_size
        return pages * v.page_size

    # -- BBT/NBT entry serialization (one entry each) --------------------
    def _bbt_entry_bytes(self, blk: "_Block") -> bytes:
        """One BBTENTRY ([MS-PST] §2.2.2.7.7.3); Unicode cbEnt=24, ANSI=12."""
        v = self.v
        ent = _bref_bytes(blk.bid, blk.ib, v) + struct.pack("<HH", len(blk.payload), 1)
        if v.is_unicode:
            ent += b"\x00\x00\x00\x00"
        return ent

    def _nbt_entry_bytes(self, entry: tuple[int, int, int, int]) -> bytes:
        """One NBTENTRY ([MS-PST] §2.2.2.7.7.4); Unicode cbEnt=32, ANSI=16."""
        nid, bdata, bsub, nparent = entry
        if self.v.is_unicode:
            return struct.pack("<Q QQ I I", nid & 0xFFFFFFFF, bdata, bsub,
                               nparent & 0xFFFFFFFF, 0)
        return struct.pack("<I I I I", nid & 0xFFFFFFFF, bdata & 0xFFFFFFFF,
                           bsub & 0xFFFFFFFF, nparent & 0xFFFFFFFF)

    def _emit_btree(self, items: list, entry_fn, key_fn, cb_ent: int,
                    ptype: int, start_ib: int):
        """Emit a 1- or 2-level B-tree of leaf entries (additive — multipage).

        When all entries fit one page the result is a single leaf page,
        byte-identical to the original single-page path.  Otherwise entries are
        split across N leaf pages indexed by one intermediate page (cLevel=1)
        whose BTENTRYs carry ``key_fn(item)`` as btkey ([MS-PST] §2.2.2.7.7.2).

        Returns ``(root_bid, root_ib, [(ib, page_bytes), ...], next_ib)``.
        """
        v = self.v
        region = (v.page_size - v.page_trailer_size
                  - (4 if v.is_unicode else 0) - 4)
        per_page = region // cb_ent
        pages: list[tuple[int, bytes]] = []
        if len(items) <= per_page:
            ib = start_ib
            ents = b"".join(entry_fn(it) for it in items)
            page, bid = self._wrap_btpage(ents, len(items), cb_ent, 0, ptype, ib)
            pages.append((ib, page))
            return bid, ib, pages, ib + v.page_size

        # Multi-leaf: chunk entries, then one intermediate page over the leaves.
        leaf_brefs: list[tuple[int, int, int]] = []  # (btkey, bid, ib)
        ib = start_ib
        for i in range(0, len(items), per_page):
            chunk = items[i:i + per_page]
            ents = b"".join(entry_fn(it) for it in chunk)
            page, bid = self._wrap_btpage(ents, len(chunk), cb_ent, 0, ptype, ib)
            pages.append((ib, page))
            leaf_brefs.append((key_fn(chunk[0]), bid, ib))
            ib += v.page_size

        # Intermediate BTENTRY: btkey(w) + BREF.
        w = v.bid_size
        bt_cb_ent = w + v.bref_size
        inter_ents = b""
        for btkey, bid, leaf_ib in leaf_brefs:
            inter_ents += btkey.to_bytes(w, "little") + _bref_bytes(bid, leaf_ib, v)
        inter_ib = ib
        inter_page, inter_bid = self._wrap_btpage(
            inter_ents, len(leaf_brefs), bt_cb_ent, 1, ptype, inter_ib)
        pages.append((inter_ib, inter_page))
        return inter_bid, inter_ib, pages, inter_ib + v.page_size

    def build(self) -> bytes:
        """Assemble the full store image with a correct HEADER + ROOT."""
        v = self.v
        # Header occupies whole page(s) so blocks start page-aligned.
        header_region = self._header_region()
        block_start = header_region
        after_blocks = self._layout_blocks(block_start)

        bbt_bid, bbt_ib, bbt_pages, after_bbt = self._emit_btree(
            self.blocks, self._bbt_entry_bytes, lambda b: b.bid,
            24 if v.is_unicode else 12, PTYPE_BBT, after_blocks)
        nbt_bid, nbt_ib, nbt_pages, ib_file_eof = self._emit_btree(
            self.nbt_entries, self._nbt_entry_bytes, lambda e: e[0] & 0xFFFFFFFF,
            32 if v.is_unicode else 16, PTYPE_NBT, after_bbt)

        header = self._emit_header(
            bref_nbt=(nbt_bid, nbt_ib),
            bref_bbt=(bbt_bid, bbt_ib),
            ib_file_eof=ib_file_eof,
            ib_amap_last=block_start,
        )

        # Assemble.
        out = bytearray(ib_file_eof)
        out[0:len(header)] = header
        for blk in self.blocks:
            data = _emit_block(blk, v)
            out[blk.ib:blk.ib + len(data)] = data
        for ib, page in bbt_pages + nbt_pages:
            out[ib:ib + len(page)] = page
        return bytes(out)

    def _emit_root(self, bref_nbt, bref_bbt, ib_file_eof, ib_amap_last,
                   f_amap_valid: int = 0x02) -> bytes:
        """Serialize the ROOT ([MS-PST] §2.2.2.6.1)."""
        v = self.v
        w = v.bid_size
        out = b"\x00\x00\x00\x00"  # dwReserved
        out += ib_file_eof.to_bytes(w, "little")
        out += ib_amap_last.to_bytes(w, "little")
        out += (0).to_bytes(w, "little")   # cbAMapFree
        out += (0).to_bytes(w, "little")   # cbPMapFree
        out += _bref_bytes(bref_nbt[0], bref_nbt[1], v)
        out += _bref_bytes(bref_bbt[0], bref_bbt[1], v)
        out += struct.pack("<BBH", f_amap_valid, 0, 0)
        # pad to root_size
        out += b"\x00" * (v.root_size - len(out))
        assert len(out) == v.root_size
        return out

    def _emit_header(self, bref_nbt, bref_bbt, ib_file_eof, ib_amap_last) -> bytes:
        """Serialize a full HEADER (Appendix A.2 verified offsets)."""
        v = self.v
        size = self._header_region()
        buf = bytearray(size)
        buf[0:4] = b"\x21\x42\x44\x4e"                       # dwMagic !BDN
        struct.pack_into("<H", buf, 0x08, WMAGIC_CLIENT)     # wMagicClient SM
        wver = WVER_UNICODE if v.is_unicode else WVER_ANSI
        struct.pack_into("<H", buf, 0x0A, wver)              # wVer
        struct.pack_into("<H", buf, 0x0C, WVER_CLIENT)       # wVerClient

        root = self._emit_root(bref_nbt, bref_bbt, ib_file_eof, ib_amap_last)
        buf[v.root_offset:v.root_offset + len(root)] = root

        buf[v.crypt_method_offset] = self.crypt
        # bSentinel (0x80) precedes bCryptMethod.
        buf[v.crypt_method_offset - 1] = 0x80

        # CRCs (computed last, over the spec windows).
        crc_partial = compute_crc(bytes(buf[0x08:0x08 + 471]))
        struct.pack_into("<I", buf, 0x04, crc_partial)
        if v.is_unicode:
            crc_full = compute_crc(bytes(buf[0x08:0x08 + 516]))
            struct.pack_into("<I", buf, 0x020C, crc_full)
        return bytes(buf)


# ---------------------------------------------------------------------------
# High-level builders (the CONTRACTS surface)
# ---------------------------------------------------------------------------
def _message_payload(msg: dict) -> bytes:
    """Pack a message dict into a deterministic, self-describing byte blob.

    The NDB tier does not interpret node payloads, so for round-trip testing we
    just need a stable, recoverable byte string per node.  We serialize the
    common envelope fields + any extra ``props`` as a length-prefixed record so
    tests can assert exact equality and later LTP fixtures can swap in real HN
    payloads under the same node id.
    """
    parts = []
    for key in ("subject", "sender", "to", "body"):
        val = msg.get(key, "")
        b = val.encode("utf-16-le") if isinstance(val, str) else bytes(val)
        parts.append(struct.pack("<I", len(b)) + b)
    props = msg.get("props", {})
    parts.append(struct.pack("<I", len(props)))
    for tag in sorted(props):
        v = props[tag]
        parts.append(struct.pack("<II", tag, len(v)) + v)
    return b"".join(parts)


def _apply_corrupt(image: bytes, corrupt: Optional[str], variant: Variant) -> bytes:
    """Apply a single corruption knob for the recovery tier."""
    if not corrupt:
        return image
    buf = bytearray(image)
    if corrupt == "truncate":
        return bytes(buf[: len(buf) // 2])
    if corrupt == "bad_header_crc":
        # Flip dwCRCPartial so the advisory check fails (must NOT abort).
        struct.pack_into("<I", buf, 0x04, (buf[0x04] ^ 0xFF))
        return bytes(buf)
    if corrupt == "zero_amap":
        # Mark fAMapValid invalid in ROOT (offset of f_amap_valid within ROOT).
        w = variant.bid_size
        famap_off = variant.root_offset + 4 + 4 * w + 2 * variant.bref_size
        if famap_off < len(buf):
            buf[famap_off] = 0x00
        return bytes(buf)
    if corrupt == "drop_nbt_entry":
        # Decrement cEnt on the NBT page so the last node disappears. The NBT
        # page is the final page in the image.
        page = variant.page_size
        nbt_start = len(buf) - page
        pad = 4 if variant.is_unicode else 0
        cent_off = nbt_start + page - variant.page_trailer_size - pad - 4
        if buf[cent_off] > 0:
            buf[cent_off] -= 1
        return bytes(buf)
    raise ValueError(f"unknown corrupt mode: {corrupt!r}")


def build_unicode_pst(*, messages: Iterable[dict], crypt: int = CRYPT_NONE,
                      folders=None, corrupt: Optional[str] = None,
                      big_message: bool = False) -> bytes:
    """Build a byte-accurate Unicode PST (CONTRACTS §"Test fixtures").

    Each message becomes one normal-message node (nidType 0x04).  When
    ``big_message`` is set, the FIRST message's payload is split across two data
    blocks under an XBLOCK to exercise reassembly.  ``crypt`` selects the data
    encode method (NONE/PERMUTE/CYCLIC).  ``folders`` is accepted for API
    compatibility; folder hierarchy is the messaging tier's concern.
    """
    return _build_pst(UNICODE, messages, crypt, corrupt, big_message)


def build_ansi_pst(*, messages: Iterable[dict], crypt: int = CRYPT_NONE,
                   corrupt: Optional[str] = None,
                   big_message: bool = False) -> bytes:
    """Build a byte-accurate ANSI PST (CONTRACTS §"Test fixtures")."""
    return _build_pst(ANSI, messages, crypt, corrupt, big_message)


def _build_pst(variant: Variant, messages: Iterable[dict], crypt: int,
               corrupt: Optional[str], big_message: bool) -> bytes:
    b = _PstBuilder(variant, crypt)
    messages = list(messages)
    for idx, msg in enumerate(messages):
        payload = _message_payload(msg)
        nid = make_nid(NID_TYPE_NORMAL_MESSAGE, idx + 1)

        bid_sub = 0
        sub = msg.get("subnodes")  # optional: {local_nid: bytes}
        if sub:
            sl_entries = []
            for local_nid, sub_payload in sub.items():
                sb = b.add_data_block(sub_payload)
                sl_entries.append((local_nid, sb, 0))
            bid_sub = b.add_slblock(sl_entries)

        if big_message and idx == 0 and len(payload) > 8:
            half = len(payload) // 2
            d1 = b.add_data_block(payload[:half])
            d2 = b.add_data_block(payload[half:])
            bid_data = b.add_xblock([d1, d2], len(payload))
        else:
            bid_data = b.add_data_block(payload)

        b.add_node(nid, bid_data, bid_sub, nid_parent=0x122)

    image = b.build()
    return _apply_corrupt(image, corrupt, variant)


# ---------------------------------------------------------------------------
# MSG (CFBF / OLE) builder
# ---------------------------------------------------------------------------
def build_msg(*, props: dict, recipients: Iterable[dict] = (),
              attachments: Iterable[dict] = ()) -> bytes:
    """Build a minimal CFBF/OLE MSG via ``olefile`` if available, else raw.

    Produces a Compound File whose root holds ``__properties_version1.0`` plus
    ``__substg1.0_%08X`` streams for each variable property, and one storage per
    recipient/attachment (``__recip_version1.0_#%08X`` / ``__attach_*``) per
    [MS-OXMSG] §2.  The NDB tier does not parse MSG, but the synth contract
    requires this builder for the MSG tier; we emit a spec-correct directory so
    those tests have an oracle.

    If ``olefile`` is not installed this falls back to writing the stream
    bytes in a flat, self-describing container the MSG tier's carve hook can
    still read; the MSG tier replaces this with a true CFBF writer if needed.
    """
    streams: dict[str, bytes] = {}

    # Fixed 8-byte top-level __properties header + 16B entries ([MS-OXMSG] §2.4).
    prop_entries = bytearray()
    prop_entries += b"\x00" * 8  # reserved(8) top-level header
    from ..proptypes import split_tag, fixed_size
    for tag, value in sorted(props.items()):
        pid, ptype = split_tag(tag)
        fsz = fixed_size(ptype)
        flags = 0x00000006  # fixed pattern: read+writable
        if fsz is not None and fsz <= 8:
            val8 = (value + b"\x00" * 8)[:8]
            prop_entries += struct.pack("<II", tag, flags) + val8
        else:
            name = f"__substg1.0_{tag:08X}"
            streams[name] = value
            prop_entries += struct.pack("<IIII", tag, flags, len(value), 0)
    streams["__properties_version1.0"] = bytes(prop_entries)

    return _write_cfbf(streams, recipients, attachments, props)


def _write_cfbf(streams: dict, recipients, attachments, props) -> bytes:
    """Write a CFBF file using olefile if present, else a flat fallback."""
    try:
        import olefile  # noqa: F401
        have_ole = True
    except Exception:
        have_ole = False

    if have_ole:
        return _write_cfbf_minimal(streams)
    # Flat fallback container: b"MSGFLAT\0" + repeated (nameLen,name,dataLen,data)
    out = bytearray(b"MSGFLAT\x00")
    for name, data in streams.items():
        nb = name.encode("utf-16-le")
        out += struct.pack("<I", len(nb)) + nb
        out += struct.pack("<I", len(data)) + data
    return bytes(out)


def _write_cfbf_minimal(streams: dict) -> bytes:
    """Emit a real, minimal CFBF (compound file) holding ``streams`` at root.

    Implements just enough of [MS-CFB] to be readable by ``olefile``:
    512-byte sectors, a single FAT sector, a directory with the Root Entry and
    one stream entry per item, and a mini-FAT for streams < 4096 bytes.
    For simplicity all streams are stored in the **mini-stream** (CFB §2.4),
    which keeps the layout tiny and deterministic.
    """
    SECTOR = 512
    MINISECTOR = 64
    ENDOFCHAIN = 0xFFFFFFFE
    FREESECT = 0xFFFFFFFF
    FATSECT = 0xFFFFFFFD

    # CFB directory entries form a red-black tree keyed by the [MS-CFB] §2.6.4
    # name collation: shorter UTF-16 names sort first, ties broken by the
    # upper-cased name.  ``olefile`` walks that tree by left/right child links, so
    # emitting a pure right-sibling chain is only correct when the names are in
    # ascending collation order.  Sort here so any stream count round-trips.
    def _cfb_key(name: str) -> tuple[int, str]:
        return (len(name), name.upper())

    names = sorted(streams.keys(), key=_cfb_key)

    # --- mini stream: concatenate streams on 64-byte boundaries ---
    mini = bytearray()
    mini_starts = []
    for name in names:
        mini_starts.append(len(mini) // MINISECTOR)
        data = streams[name]
        mini += data
        pad = (-len(data)) % MINISECTOR
        mini += b"\x00" * pad
    mini_sectors = len(mini) // MINISECTOR

    # mini-FAT chain
    minifat = []
    cursor = 0
    for name in names:
        n = (len(streams[name]) + MINISECTOR - 1) // MINISECTOR or 1
        for j in range(n):
            minifat.append(cursor + j + 1 if j < n - 1 else ENDOFCHAIN)
        cursor += n
    while len(minifat) % (SECTOR // 4):
        minifat.append(FREESECT)

    # --- directory entries ---
    def dir_entry(name, etype, color, left, right, child, start, size):
        nb = name.encode("utf-16-le") + b"\x00\x00"
        nb = nb[:64].ljust(64, b"\x00")
        return struct.pack(
            "<64sHBBIII16sIQQIQ",
            nb, min(len(name) * 2 + 2, 64), etype, color,
            left, right, child, b"\x00" * 16, 0, 0, 0, start, size,
        )

    # Big-sector layout (sector 0 = FAT, then directory / mini-FAT / mini-stream
    # chains, each possibly spanning several sectors).  Pre-compute sector counts
    # so the Root Entry can reference the mini-stream's start sector below.
    fat_sector = 0
    num_dir_entries = len(names) + 1  # +1 Root Entry
    dir_nsect = (num_dir_entries * 128 + SECTOR - 1) // SECTOR
    minifat_nsect = (len(minifat) * 4 + SECTOR - 1) // SECTOR
    ministream_nsect = (len(mini) + SECTOR - 1) // SECTOR

    dir_sector = 1
    minifat_sector = dir_sector + dir_nsect
    ministream_first = minifat_sector + minifat_nsect
    ministream_start = ministream_first if mini else ENDOFCHAIN

    # Stream entries occupy directory indices 1..len(names); Root Entry is 0.
    # Build a *balanced* BST over the collation-sorted names ([MS-CFB] §2.6.4)
    # so ``olefile`` (which recurses left/right) reads every entry — a pure
    # right-sibling chain silently drops entries past the first when the tree is
    # walked recursively.
    NOSTREAM = 0xFFFFFFFF
    left = [NOSTREAM] * len(names)
    right = [NOSTREAM] * len(names)

    def _balance(lo: int, hi: int) -> int:
        """Wire ``names[lo:hi+1]`` into a balanced BST; return the root dir index."""
        if lo > hi:
            return NOSTREAM
        mid = (lo + hi) // 2
        left[mid] = _balance(lo, mid - 1)
        right[mid] = _balance(mid + 1, hi)
        return mid + 1  # +1: directory index 0 is the Root Entry

    child_root = _balance(0, len(names) - 1) if names else NOSTREAM

    entries = [dir_entry("Root Entry", 5, 0,
                         NOSTREAM, NOSTREAM, child_root,
                         ministream_start, len(mini))]
    for i, name in enumerate(names):
        entries.append(dir_entry(name, 2, 1, left[i], right[i], NOSTREAM,
                                 mini_starts[i], len(streams[name])))
    dir_bytes = b"".join(entries)
    dir_bytes += b"\x00" * ((-len(dir_bytes)) % SECTOR)

    minifat_bytes = b"".join(struct.pack("<I", x) for x in minifat)
    minifat_bytes += b"\x00" * ((-len(minifat_bytes)) % SECTOR)
    mini_bytes = bytes(mini) + b"\x00" * ((-len(mini)) % SECTOR)

    # --- FAT: chain each multi-sector region (directory, mini-FAT, mini-stream) ---
    fat = [FREESECT] * (SECTOR // 4)
    fat[fat_sector] = FATSECT

    def _chain(first: int, count: int) -> None:
        """Mark a ``count``-sector region starting at ``first`` as a FAT chain."""
        for s in range(first, first + count):
            fat[s] = (s + 1) if s + 1 < first + count else ENDOFCHAIN

    _chain(dir_sector, dir_nsect)
    _chain(minifat_sector, minifat_nsect)
    _chain(ministream_first, ministream_nsect)
    fat_bytes = b"".join(struct.pack("<I", x) for x in fat)

    # --- CFB header (512 bytes) ---
    header = bytearray(512)
    header[0:8] = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"  # CFB signature
    struct.pack_into("<H", header, 24, 0x003E)  # minor version
    struct.pack_into("<H", header, 26, 0x0003)  # major version (512 sectors)
    struct.pack_into("<H", header, 28, 0xFFFE)  # byte order
    struct.pack_into("<H", header, 30, 9)       # sector shift 2^9=512
    struct.pack_into("<H", header, 32, 6)       # mini sector shift 2^6=64
    struct.pack_into("<I", header, 44, 1)       # number of FAT sectors
    struct.pack_into("<I", header, 48, dir_sector)        # first dir sector
    struct.pack_into("<I", header, 56, 4096)    # mini stream cutoff
    struct.pack_into("<I", header, 60, minifat_sector)    # first mini-FAT sector
    struct.pack_into("<I", header, 64, minifat_nsect)     # num mini-FAT sectors
    struct.pack_into("<I", header, 68, ENDOFCHAIN)        # first DIFAT sector
    struct.pack_into("<I", header, 72, 0)                 # num DIFAT sectors
    # DIFAT array (first 109 entries) at offset 76: FAT located at sector 0
    struct.pack_into("<I", header, 76, fat_sector)
    for k in range(1, 109):
        struct.pack_into("<I", header, 76 + k * 4, FREESECT)

    out = bytes(header) + fat_bytes + dir_bytes + minifat_bytes + mini_bytes
    return out


# ===========================================================================
# Rich messaging-tier fixtures (additive — keeps build_unicode_pst intact)
#
# The messaging tier needs a *real* LTP payload: folder Property Contexts,
# hierarchy/contents Table Contexts, message PCs with recipient/attachment
# subnode TCs, and an embedded-message PC nested under an attachment subnode.
# Everything below assembles spec-correct HN/PC/TC bytes (the same geometry the
# LTP tier round-trips in test_ltp) and registers them as NDB nodes/subnodes via
# the existing ``_PstBuilder`` so ``NodeDatabase`` reads them unchanged.
#
# [MS-PST] §2.3.1 (HN), §2.3.2 (BTH), §2.3.3 (PC), §2.3.4 (TC),
# §2.4.4 (folder hierarchy/contents tables), §2.4.5/§2.4.6 (message
# recipient/attachment subnode tables).  Appendix A H17 (named-prop map).
# ===========================================================================
from ..ndb.bref import (  # noqa: E402  (additive imports kept local to section)
    NID_NAME_TO_ID_MAP,
    NID_MESSAGE_STORE,
    NID_ROOT_FOLDER,
    NID_TYPE_NORMAL_FOLDER,
    NID_TYPE_HIERARCHY_TABLE,
    NID_TYPE_CONTENTS_TABLE,
    NID_TYPE_ASSOC_CONTENTS_TABLE,
    nid_index,
)
from ..ltp.heap import HN_CLIENT_PC, HN_CLIENT_TC  # noqa: E402
from ..proptypes import is_inline_in_pc, make_tag, PropType, split_tag  # noqa: E402

# PidTagLtpRowId column tag (the dwRowID column at row offset 0, [MS-PST] §2.3.4.3.1).
_PID_LTP_ROW_ID = make_tag(0x6748, PropType.INTEGER32)        # 0x67480003
_PID_LTP_ROW_VER = make_tag(0x67E9, PropType.INTEGER32)       # 0x67E90003

# Envelope PidTag ids the messaging tier reads.
_PID_DISPLAY_NAME = make_tag(0x3001, PropType.STRING)
_PID_SUBJECT = make_tag(0x0037, PropType.STRING)
_PID_SENDER_NAME = make_tag(0x0C1A, PropType.STRING)
_PID_SENDER_EMAIL = make_tag(0x0C1F, PropType.STRING)
_PID_RECORD_KEY = make_tag(0x0FF9, PropType.BINARY)
_PID_IPM_SUBTREE = make_tag(0x35E0, PropType.BINARY)
_PID_PST_PASSWORD = make_tag(0x67FF, PropType.INTEGER32)
_PID_CONTENT_COUNT = make_tag(0x3602, PropType.INTEGER32)
_PID_SUBFOLDERS = make_tag(0x360A, PropType.BOOLEAN)
_PID_EMAIL_ADDRESS = make_tag(0x3003, PropType.STRING)
_PID_ADDRTYPE = make_tag(0x3002, PropType.STRING)
_PID_RECIPIENT_TYPE = make_tag(0x0C15, PropType.INTEGER32)
_PID_ATTACH_METHOD = make_tag(0x3705, PropType.INTEGER32)
_PID_ATTACH_LONG_FN = make_tag(0x3707, PropType.STRING)
_PID_ATTACH_FN = make_tag(0x3704, PropType.STRING)
_PID_ATTACH_SIZE = make_tag(0x0E20, PropType.INTEGER32)
_PID_ATTACH_DATA_BIN = make_tag(0x3701, PropType.BINARY)      # 0x37010102
_PID_ATTACH_DATA_OBJ = make_tag(0x3701, PropType.OBJECT)      # 0x3701000D
_PID_NAMEID_GUID = make_tag(0x0002, PropType.BINARY)
_PID_NAMEID_ENTRY = make_tag(0x0003, PropType.BINARY)
_PID_NAMEID_STRING = make_tag(0x0004, PropType.BINARY)
_PID_BODY = make_tag(0x1000, PropType.STRING)                 # PidTagBody
_PID_DELIVERY_TIME = make_tag(0x0E06, PropType.TIME)          # PidTagMessageDeliveryTime
_PID_MESSAGE_CLASS = make_tag(0x001A, PropType.STRING)        # PidTagMessageClass

# Subnode local-NID templates ([MS-PST] §2.4.5.3 / §2.4.6.1).
SUBNODE_RECIPIENT_TC = 0x692
SUBNODE_ATTACHMENT_TC = 0x671
SUBNODE_EMBEDDED_MSG = _PID_ATTACH_DATA_OBJ  # 0x3701000D as a subnode local-NID

# Recipient types ([MS-OXOMSG] §2.2.3.1).
MAPI_TO = 1
MAPI_CC = 2
MAPI_BCC = 3

# AttachMethod values (Appendix A H7).
ATTACH_BY_VALUE = 1
ATTACH_EMBEDDED_MSG = 5


def _make_hid(index_1based: int, block_index: int = 0) -> int:
    """Compose a HID: hidType=0, hidIndex(1-based), hidBlockIndex ([MS-PST] §2.2.2.1)."""
    return (index_1based & 0x7FF) << 5 | (block_index & 0xFFFF) << 16


def _build_heap_bytes(client_sig: int, hid_user_root: int,
                      allocations: list[bytes]) -> bytes:
    """Assemble a single-block Heap-on-Node ([MS-PST] §2.3.1).

    Layout: HNHDR(12) | alloc[0] | alloc[1] | ... | HNPAGEMAP.  User allocation
    ``i`` is 1-based hidIndex ``i+1`` (HNHDR consumes the start of the block but
    the first *user* allocation gets hidIndex 1).
    """
    body = bytearray()
    offsets = [12]
    for a in allocations:
        body += a
        offsets.append(offsets[-1] + len(a))
    ib_hnpm = 12 + len(body)
    hdr = struct.pack("<HBBII", ib_hnpm, 0xEC, client_sig, hid_user_root, 0)[:12]
    pagemap = struct.pack("<HH", len(allocations), 0)
    for o in offsets:
        pagemap += struct.pack("<H", o)
    return bytes(hdr) + bytes(body) + pagemap


def _build_bth_leaf(cb_key: int, cb_ent: int,
                    records: list[tuple[bytes, bytes]],
                    leaf_hid_index: int) -> tuple[bytes, bytes]:
    """Build a single-leaf BTH (header + leaf allocations) ([MS-PST] §2.3.2)."""
    leaf = bytearray()
    for k, v in records:
        leaf += k + v
    header = struct.pack("<BBBBI", 0xB5, cb_key, cb_ent, 0, _make_hid(leaf_hid_index))
    return header, bytes(leaf)


def build_pc_bytes(properties: dict[int, bytes]) -> bytes:
    """Build a Property-Context heap from ``{full_tag: value_bytes}`` ([MS-PST] §2.3.3).

    Fixed ≤4B types are stored inline in dwValueHnid (H5); everything else gets a
    heap allocation referenced by HID.  Allocation plan (1-based hidIndex):
    1=BTHHEADER, 2=BTH leaf, 3..=variable/large value allocations.
    """
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
        records.append((struct.pack("<H", prop_id),
                        struct.pack("<HI", ptype, hnid)))
    header, leaf = _build_bth_leaf(2, 6, records, leaf_hid_index=2)
    allocations = [header, leaf] + var_allocs
    return _build_heap_bytes(HN_CLIENT_PC, _make_hid(1), allocations)


def build_pc_bytes_with_subnode_refs(
        properties: dict[int, bytes],
        subnode_refs: dict[int, int]) -> bytes:
    """Like :func:`build_pc_bytes`, but some props reference subnode NIDs (H6).

    ``subnode_refs`` maps a full tag → subnode local-NID; that property's
    dwValueHnid is set to the NID directly (used for >3580B values and for the
    embedded-message PtypObject ``0x3701000D``).  The subnode NID's low 5 bits
    MUST be non-zero or it would read as a heap HID ([MS-PST] §2.3.3.2).
    """
    var_allocs: list[bytes] = []
    records: list[tuple[bytes, bytes]] = []
    next_index = 3
    for tag in sorted(set(properties) | set(subnode_refs)):
        _pid, ptype = split_tag(tag)
        if tag in subnode_refs:
            hnid = subnode_refs[tag]
        else:
            value = properties[tag]
            if is_inline_in_pc(ptype):
                dw = (value + b"\x00\x00\x00\x00")[:4]
                hnid = struct.unpack("<I", dw)[0]
            else:
                var_allocs.append(value)
                hnid = _make_hid(next_index)
                next_index += 1
        prop_id = (tag >> 16) & 0xFFFF
        records.append((struct.pack("<H", prop_id),
                        struct.pack("<HI", ptype, hnid)))
    header, leaf = _build_bth_leaf(2, 6, records, leaf_hid_index=2)
    allocations = [header, leaf] + var_allocs
    return _build_heap_bytes(HN_CLIENT_PC, _make_hid(1), allocations)


def build_tc_bytes(columns: list[tuple[int, int]],
                   rows: list[tuple[int, dict[int, Optional[bytes]]]],
                   ) -> tuple[bytes, dict[int, bytes]]:
    """Build a Table-Context heap whose Row Matrix lives in a subnode ([MS-PST] §2.3.4).

    Args:
        columns: ``(full_tag, cb_data)`` for each non-rowid column.
        rows: ``(dwRowID, {tag: value_or_None})``; ``None`` ⇒ absent cell (CEB 0).
            ``dwRowID`` is the child NID (folder/message/recipient/attachment) for
            hierarchy/contents/recipient/attachment tables.

    Returns:
        ``(heap_bytes, {matrix_subnode_nid: matrix_bytes})``.
    """
    cols = [(_PID_LTP_ROW_ID, 4)] + list(columns)
    col_descs = []
    ib = 0
    for i, (tag, cb) in enumerate(cols):
        col_descs.append((tag, ib, cb, i))  # iBit = column index
        ib += cb
    end_4b = ib
    n_cols = len(cols)
    ceb_bytes = (n_cols + 7) // 8
    rgib = (end_4b, end_4b, end_4b, end_4b + ceb_bytes)
    row_size = end_4b + ceb_bytes

    var_allocs: list[bytes] = []
    next_index = 4  # 1=TCINFO, 2=RowIndex BTH header, 3=RowIndex leaf, 4..=values

    matrix = bytearray()
    row_index_records: list[tuple[bytes, bytes]] = []
    for row_idx, (row_id, cells) in enumerate(rows):
        row = bytearray(row_size)
        struct.pack_into("<I", row, 0, row_id & 0xFFFFFFFF)
        ceb = bytearray(ceb_bytes)
        ceb[0] |= 0x80  # dwRowID column always present
        for tag, ib_data, cb, i_bit in col_descs:
            if tag == _PID_LTP_ROW_ID:
                continue
            val = cells.get(tag, None)
            if val is None:
                continue
            ceb[i_bit // 8] |= (0x80 >> (i_bit % 8))
            _pid, ptype = split_tag(tag)
            if is_inline_in_pc(ptype):
                cell = (val + b"\x00\x00\x00\x00")[:cb]
            else:
                var_allocs.append(val)
                cell = struct.pack("<I", _make_hid(next_index))
                next_index += 1
            row[ib_data:ib_data + cb] = cell
        row[rgib[2]:rgib[2] + ceb_bytes] = ceb
        matrix += row
        row_index_records.append(
            (struct.pack("<I", row_id & 0xFFFFFFFF), struct.pack("<I", row_idx)))

    # Row Matrix lives in a subnode (hnidRows = subnode NID — Appendix A H23).
    # Low 5 bits must be non-zero; 0x8D has nidType 0x0D.
    matrix_nid = 0x8D
    ri_header, ri_leaf = _build_bth_leaf(4, 4, row_index_records, leaf_hid_index=3)
    hid_row_index = _make_hid(2)

    tcinfo = struct.pack("<BB", 0x7C, n_cols)
    tcinfo += struct.pack("<HHHH", *rgib)
    tcinfo += struct.pack("<III", hid_row_index, matrix_nid, 0)
    for tag, ib_data, cb, i_bit in col_descs:
        tcinfo += struct.pack("<IHBB", tag, ib_data, cb, i_bit)

    allocations = [tcinfo, ri_header, ri_leaf] + var_allocs
    heap_bytes = _build_heap_bytes(HN_CLIENT_TC, _make_hid(1), allocations)
    return heap_bytes, {matrix_nid: bytes(matrix)}


def _nameid_streams(named: list[dict]) -> dict[int, bytes]:
    """Build the three name-to-id map streams as PC properties (Appendix A H17).

    Each ``named`` entry is ``{"npid_index": int, "lid": int}`` (id-named) or
    ``{"npid_index": int, "name": str, "guid": bytes16}`` (string-named).  For
    id-named props the GUID is given as raw 16 bytes and placed in the GUID
    stream; ``wGuid`` index is ``3 + position`` (entries 1/2 are the hardcoded
    PS_MAPI/PS_PUBLIC_STRINGS and are *not* in the stream).
    """
    guid_stream = bytearray()
    string_stream = bytearray()
    entry_stream = bytearray()
    guid_list: list[bytes] = []

    def guid_index(g: bytes) -> int:
        for i, existing in enumerate(guid_list):
            if existing == g:
                return 3 + i
        guid_list.append(g)
        return 3 + len(guid_list) - 1

    for ent in named:
        npid_idx = ent["npid_index"]
        g = ent["guid"]
        wguid = guid_index(g)
        if "name" in ent:
            n_flag = 1
            name_bytes = ent["name"].encode("utf-16-le")
            str_off = len(string_stream)
            string_stream += struct.pack("<I", len(name_bytes)) + name_bytes
            id_or_off = str_off
        else:
            n_flag = 0
            id_or_off = ent["lid"]
        # NAMEID (8B): propid(4) | (wGuid<<1 | N)(2) | wPropIdx(2).
        entry_stream += struct.pack(
            "<IHH", id_or_off, (wguid << 1) | n_flag, npid_idx)
    for g in guid_list:
        guid_stream += g
    return {
        _PID_NAMEID_GUID: bytes(guid_stream),
        _PID_NAMEID_ENTRY: bytes(entry_stream),
        _PID_NAMEID_STRING: bytes(string_stream),
    }


def build_unicode_pst_tree(*, store_name: str = "Personal Folders",
                           crypt: int = CRYPT_NONE,
                           named: Optional[list[dict]] = None,
                           pst_password: Optional[int] = None,
                           deleted: bool = False,
                           corrupt: Optional[str] = None) -> bytes:
    """Build a Unicode PST with a folder tree, messages, recipients & attachments.

    Layout produced (NIDs share ``nidIndex`` across the PC + 3 TCs, [MS-PST] §2.4):

    * Message store PC (NID 0x21) → DisplayName/RecordKey/IpmSubTreeEntryId →
      root folder NID 0x122, plus optional PstPassword.
    * Name-to-id map PC (NID 0x61) holding the three named-prop streams.
    * Root folder (nidIndex 9 → 0x122) with one subfolder "Inbox" (nidIndex 10).
    * "Inbox" contents table with two messages; the first message carries two
      recipients (To + Cc), one by-value attachment, and one embedded message.

    This is the canonical messaging-tier oracle; the messaging public API
    (open_store) must round-trip every name/address/byte asserted in
    test_messaging.
    """
    b = _PstBuilder(UNICODE, crypt)

    def add_pc_node(nid: int, props: dict[int, bytes], parent: int,
                    subnodes: Optional[list[tuple[int, bytes, int]]] = None) -> None:
        bid_sub = 0
        if subnodes:
            bid_sub = b.add_slblock(subnodes)
        bid_data = b.add_data_block(build_pc_bytes(props))
        b.add_node(nid, bid_data, bid_sub, nid_parent=parent)

    def add_raw_node(nid: int, payload: bytes, parent: int,
                     subnodes: Optional[list[tuple[int, bytes, int]]] = None) -> None:
        bid_sub = 0
        if subnodes:
            bid_sub = b.add_slblock(subnodes)
        bid_data = b.add_data_block(payload)
        b.add_node(nid, bid_data, bid_sub, nid_parent=parent)

    def sub_tc(local_nid: int, heap_bytes: bytes, matrix: dict[int, bytes]
               ) -> tuple[int, bytes, int]:
        """Register a TC's row-matrix subnode and return the TC SLENTRY tuple.

        The TC heap itself is a data block; its row matrix is a *nested* subnode
        of the TC subnode (the SLENTRY's bidSub).
        """
        (m_nid, m_bytes), = matrix.items()
        m_block = b.add_data_block(m_bytes)
        inner_sl = b.add_slblock([(m_nid, m_block, 0)])
        tc_block = b.add_data_block(heap_bytes)
        return (local_nid, tc_block, inner_sl)

    def sub_pc(local_nid: int, props: dict[int, bytes],
               sub_refs: Optional[dict[int, int]] = None,
               nested: Optional[list[tuple[int, bytes, int]]] = None
               ) -> tuple[int, bytes, int]:
        """Register a PC subnode (optionally with its own nested subnodes)."""
        if sub_refs:
            payload = build_pc_bytes_with_subnode_refs(props, sub_refs)
        else:
            payload = build_pc_bytes(props)
        bid_data = b.add_data_block(payload)
        bid_sub = b.add_slblock(nested) if nested else 0
        return (local_nid, bid_data, bid_sub)

    # ---- message store PC (NID 0x21) ----
    root_eid = _entryid_for_nid(NID_ROOT_FOLDER)
    store_props = {
        _PID_DISPLAY_NAME: store_name.encode("utf-16-le"),
        _PID_RECORD_KEY: b"\x11" * 16,
        _PID_IPM_SUBTREE: root_eid,
    }
    if pst_password is not None:
        store_props[_PID_PST_PASSWORD] = struct.pack("<I", pst_password)
    add_pc_node(NID_MESSAGE_STORE, store_props, parent=0)

    # ---- name-to-id map PC (NID 0x61) ----
    if named:
        add_pc_node(NID_NAME_TO_ID_MAP, _nameid_streams(named), parent=0)

    # ---- folders ----
    root_index = nid_index(NID_ROOT_FOLDER)        # 9
    inbox_index = root_index + 1                    # 10
    inbox_pc_nid = make_nid(NID_TYPE_NORMAL_FOLDER, inbox_index)

    # Messages in Inbox: msg1 (rich), msg2 (plain).
    msg1_nid = make_nid(NID_TYPE_NORMAL_MESSAGE, 1)
    msg2_nid = make_nid(NID_TYPE_NORMAL_MESSAGE, 2)

    # ----- Root folder PC + hierarchy/contents/FAI TCs -----
    add_pc_node(make_nid(NID_TYPE_NORMAL_FOLDER, root_index),
                {_PID_DISPLAY_NAME: store_name.encode("utf-16-le"),
                 _PID_CONTENT_COUNT: struct.pack("<I", 0),
                 _PID_SUBFOLDERS: struct.pack("<H", 1)},
                parent=NID_MESSAGE_STORE)

    # Hierarchy TC: one row → Inbox subfolder (dwRowID = subfolder PC NID).
    h_heap, h_mat = build_tc_bytes(
        [(_PID_DISPLAY_NAME, 4)],
        [(inbox_pc_nid, {_PID_DISPLAY_NAME: "Inbox".encode("utf-16-le")})])
    add_raw_node(make_nid(NID_TYPE_HIERARCHY_TABLE, root_index), h_heap,
                 parent=NID_MESSAGE_STORE, subnodes=[_only_sub(b, h_mat)])
    # Empty contents/FAI TCs for the root.
    _add_empty_tc(b, make_nid(NID_TYPE_CONTENTS_TABLE, root_index))
    _add_empty_tc(b, make_nid(NID_TYPE_ASSOC_CONTENTS_TABLE, root_index))

    # ----- Inbox folder PC + TCs -----
    add_pc_node(inbox_pc_nid,
                {_PID_DISPLAY_NAME: "Inbox".encode("utf-16-le"),
                 _PID_CONTENT_COUNT: struct.pack("<I", 2),
                 _PID_SUBFOLDERS: struct.pack("<H", 0)},
                parent=make_nid(NID_TYPE_NORMAL_FOLDER, root_index))
    # Inbox hierarchy TC: empty (no subfolders).
    _add_empty_tc(b, make_nid(NID_TYPE_HIERARCHY_TABLE, inbox_index))
    # Inbox contents TC: two rows (dwRowID = message NID).
    c_heap, c_mat = build_tc_bytes(
        [(_PID_SUBJECT, 4)],
        [(msg1_nid, {_PID_SUBJECT: "Wire transfer".encode("utf-16-le")}),
         (msg2_nid, {_PID_SUBJECT: "Lunch?".encode("utf-16-le")})])
    add_raw_node(make_nid(NID_TYPE_CONTENTS_TABLE, inbox_index), c_heap,
                 parent=inbox_pc_nid, subnodes=[_only_sub(b, c_mat)])
    _add_empty_tc(b, make_nid(NID_TYPE_ASSOC_CONTENTS_TABLE, inbox_index))

    # ----- Message 1: PC + recipient TC + attachment TC + attachment PC -----
    # Recipient TC (subnode 0x692): To + Cc rows.
    rcpt_heap, rcpt_mat = build_tc_bytes(
        [(_PID_DISPLAY_NAME, 4), (_PID_EMAIL_ADDRESS, 4),
         (_PID_ADDRTYPE, 4), (_PID_RECIPIENT_TYPE, 4)],
        [(0x01, {_PID_DISPLAY_NAME: "Alice".encode("utf-16-le"),
                 _PID_EMAIL_ADDRESS: "alice@example.com".encode("utf-16-le"),
                 _PID_ADDRTYPE: "SMTP".encode("utf-16-le"),
                 _PID_RECIPIENT_TYPE: struct.pack("<I", MAPI_TO)}),
         (0x02, {_PID_DISPLAY_NAME: "Bob".encode("utf-16-le"),
                 _PID_EMAIL_ADDRESS: "bob@example.com".encode("utf-16-le"),
                 _PID_ADDRTYPE: "SMTP".encode("utf-16-le"),
                 _PID_RECIPIENT_TYPE: struct.pack("<I", MAPI_CC)})])

    # Attachment table TC (subnode 0x671): one row, dwRowID = attachment PC NID.
    attach_local_nid = 0x21  # nidType 0x01 internal — non-zero low bits
    att_heap, att_mat = build_tc_bytes(
        [(_PID_ATTACH_LONG_FN, 4), (_PID_ATTACH_METHOD, 4)],
        [(attach_local_nid,
          {_PID_ATTACH_LONG_FN: "invoice.pdf".encode("utf-16-le"),
           _PID_ATTACH_METHOD: struct.pack("<I", ATTACH_BY_VALUE)})])

    # Embedded-message PC: a nested subnode (0x3701000D) under the attachment PC.
    embed_props = {
        _PID_SUBJECT: "Embedded note".encode("utf-16-le"),
        _PID_SENDER_NAME: "Carol".encode("utf-16-le"),
        _PID_SENDER_EMAIL: "carol@example.com".encode("utf-16-le"),
    }
    embedded_sub = sub_pc(SUBNODE_EMBEDDED_MSG, embed_props)

    attach_data = b"%PDF-1.7 fake invoice bytes"
    # Attachment 1 PC (by-value): data binary inline as a heap value.
    attach1 = sub_pc(
        attach_local_nid,
        {_PID_ATTACH_LONG_FN: "invoice.pdf".encode("utf-16-le"),
         _PID_ATTACH_FN: "invoice.pdf".encode("utf-16-le"),
         _PID_ATTACH_METHOD: struct.pack("<I", ATTACH_BY_VALUE),
         _PID_ATTACH_SIZE: struct.pack("<I", len(attach_data)),
         _PID_ATTACH_DATA_BIN: attach_data})

    # Attachment 2 PC (embedded message): method 5 + 0x3701000D subnode ref.
    attach2_local_nid = 0x25  # nidType 0x05 attachment, non-zero low bits
    attach2 = sub_pc(
        attach2_local_nid,
        {_PID_ATTACH_LONG_FN: "forwarded.msg".encode("utf-16-le"),
         _PID_ATTACH_METHOD: struct.pack("<I", ATTACH_EMBEDDED_MSG)},
        sub_refs={_PID_ATTACH_DATA_OBJ: SUBNODE_EMBEDDED_MSG},
        nested=[embedded_sub])

    # Second attachment row in the attachment TC.
    att2_heap, att2_mat = build_tc_bytes(
        [(_PID_ATTACH_LONG_FN, 4), (_PID_ATTACH_METHOD, 4)],
        [(attach_local_nid,
          {_PID_ATTACH_LONG_FN: "invoice.pdf".encode("utf-16-le"),
           _PID_ATTACH_METHOD: struct.pack("<I", ATTACH_BY_VALUE)}),
         (attach2_local_nid,
          {_PID_ATTACH_LONG_FN: "forwarded.msg".encode("utf-16-le"),
           _PID_ATTACH_METHOD: struct.pack("<I", ATTACH_EMBEDDED_MSG)})])

    msg1_subnodes = [
        sub_tc(SUBNODE_RECIPIENT_TC, rcpt_heap, rcpt_mat),
        sub_tc(SUBNODE_ATTACHMENT_TC, att2_heap, att2_mat),
        attach1,
        attach2,
    ]
    msg1_props = {
        _PID_SUBJECT: "Wire transfer".encode("utf-16-le"),
        _PID_SENDER_NAME: "Eve Sender".encode("utf-16-le"),
        _PID_SENDER_EMAIL: "eve@example.com".encode("utf-16-le"),
        _PID_BODY: "Please wire $1,000,000 today.".encode("utf-16-le"),
        # PidTagMessageDeliveryTime (0x0E06): 2021-06-15T12:00:00Z FILETIME.
        _PID_DELIVERY_TIME: struct.pack("<Q", 132682320000000000),
        _PID_MESSAGE_CLASS: "IPM.Note".encode("utf-16-le"),
    }
    add_pc_node(msg1_nid, msg1_props, parent=inbox_pc_nid, subnodes=msg1_subnodes)

    # ----- Message 2: plain PC, no recipients/attachments -----
    add_pc_node(msg2_nid, {
        _PID_SUBJECT: "Lunch?".encode("utf-16-le"),
        _PID_SENDER_NAME: "Frank".encode("utf-16-le"),
        _PID_SENDER_EMAIL: "frank@example.com".encode("utf-16-le"),
        _PID_MESSAGE_CLASS: "IPM.Note".encode("utf-16-le"),
    }, parent=inbox_pc_nid)

    # ----- Optional deleted/orphaned message (recovery-tier oracle) -----
    # A normal-message node whose NBT entry survives but which NO live folder
    # contents TC references — i.e. a hard-deleted item recoverable by the
    # trusted-walk-minus-reachable cascade (PLAN §8.2 / §7.3).
    if deleted:
        del_nid = make_nid(NID_TYPE_NORMAL_MESSAGE, 0x7777)
        add_pc_node(del_nid, {
            _PID_SUBJECT: "Deleted secret".encode("utf-16-le"),
            _PID_SENDER_NAME: "Mallory".encode("utf-16-le"),
            _PID_SENDER_EMAIL: "mallory@evil.example".encode("utf-16-le"),
            _PID_BODY: "This message was deleted.".encode("utf-16-le"),
            _PID_MESSAGE_CLASS: "IPM.Note".encode("utf-16-le"),
        }, parent=inbox_pc_nid)

    image = b.build()
    if corrupt == "truncate":
        # Drop the trailing BBT+NBT page region so the trusted ROOT walk cannot
        # reach the B-trees, while keeping every data block (the message PCs) in
        # the survivor prefix — the AC-2 carve-recovery oracle (PLAN §7.2).
        image = image[: len(image) - 2 * UNICODE.page_size]
    elif corrupt is not None:
        image = _apply_corrupt(image, corrupt, UNICODE)
    return image


def _entryid_for_nid(nid: int) -> bytes:
    """Minimal 24-byte folder EntryID whose trailing 4 bytes are the NID.

    [MS-OXCDATA] §2.2.4.1: flags(4) + providerUID(16) + NID(4).  The messaging
    tier only needs the trailing NID to locate the root folder.
    """
    return struct.pack("<I", 0) + b"\x22" * 16 + struct.pack("<I", nid & 0xFFFFFFFF)


def _only_sub(builder: "_PstBuilder", matrix: dict[int, bytes]
              ) -> tuple[int, int, int]:
    """Register a single row-matrix subnode and return its SLENTRY tuple."""
    (m_nid, m_bytes), = matrix.items()
    m_block = builder.add_data_block(m_bytes)
    return (m_nid, m_block, 0)


def _add_empty_tc(builder: "_PstBuilder", nid: int) -> None:
    """Register an empty contents/hierarchy/FAI TC (no rows)."""
    heap, mat = build_tc_bytes([(_PID_SUBJECT, 4)], [])
    builder.add_node(nid, builder.add_data_block(heap), 0)
