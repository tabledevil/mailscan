"""Known-answer test vectors for the render/ subpackage (PLAN §9, §0.5).

Every byte-level constant is locked here with a spec citation in a comment.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone

import pytest

from pstforensic.exceptions import WarnCode, WarningSink
from pstforensic.mapi import MapiObject, MapiValue
from pstforensic.ndb.crc import compute_crc
from pstforensic.proptypes import PropType, make_tag
from pstforensic.render import (
    conversation_index,
    decode_string,
    decompress_rtf,
    entryid,
    filetime,
    guid,
    install_renderer,
    render_currency,
    render_value,
)
from pstforensic.render.filetime import apptime, filetime_note
from pstforensic.render.rtf import RTF_INIT_DICT_LEN, _INIT_DICT


# --------------------------------------------------------------------------- #
# FILETIME  ([MS-DTYP] FILETIME; PLAN §9.3)
# --------------------------------------------------------------------------- #
def _ft_bytes(dt: datetime) -> bytes:
    """Encode a UTC datetime as a u64 LE FILETIME (test oracle)."""
    delta = dt - datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks = int(delta.total_seconds() * 10_000_000)
    return struct.pack("<Q", ticks)


def test_filetime_known_date():
    # 2009-07-14T12:00:00Z. Verified: ticks since 1601 for this instant.
    dt = datetime(2009, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    raw = _ft_bytes(dt)
    # Known anchor: this exact tick count.
    assert struct.unpack("<Q", raw)[0] == 128920464000000000
    assert filetime(raw) == dt


def test_filetime_unix_epoch_anchor():
    # FILETIME of the Unix epoch is exactly 116444736000000000 ([MS-DTYP]).
    raw = struct.pack("<Q", 116444736000000000)
    assert filetime(raw) == datetime(1970, 1, 1, tzinfo=timezone.utc)


def test_filetime_zero_is_never():
    assert filetime(b"\x00" * 8) is None
    assert filetime_note(b"\x00" * 8) == "never"


def test_filetime_out_of_range():
    raw = struct.pack("<Q", 0xFFFFFFFFFFFFFFFF)
    assert filetime(raw) is None
    assert filetime_note(raw).startswith("(invalid")


def test_apptime_ole_date():
    # OLE automation date 0.0 == 1899-12-30; 1.0 == 1899-12-31; 39995.5 noon.
    assert apptime(struct.pack("<d", 0.0)) == datetime(
        1899, 12, 30, tzinfo=timezone.utc
    )
    assert apptime(struct.pack("<d", 1.5)) == datetime(
        1899, 12, 31, 12, 0, 0, tzinfo=timezone.utc
    )


# --------------------------------------------------------------------------- #
# GUID  ([MS-DTYP] GUID; PLAN §9.4)  — mixed-endian first three groups
# --------------------------------------------------------------------------- #
def test_guid_byte_order():
    # PS_PUBLIC_STRINGS {00020329-0000-0000-C000-000000000046} stored on disk.
    raw = bytes.fromhex("29030200" "0000" "0000" "c000000000000046")
    assert guid(raw) == "00020329-0000-0000-c000-000000000046"


def test_guid_mixed_endian_distinct_groups():
    # Distinct bytes to prove group ordering: Data1 LE, Data2 LE, Data3 LE.
    raw = bytes.fromhex("01020304" "0506" "0708" "090a0b0c0d0e0f10")
    assert guid(raw) == "04030201-0605-0807-090a-0b0c0d0e0f10"


def test_guid_annotation():
    raw = bytes.fromhex("29030200000000000c0000000000000046".rjust(32, "0"))
    s = guid(
        bytes.fromhex("2903020000000000c000000000000046"),
        known={"00020329-0000-0000-c000-000000000046": "PS_PUBLIC_STRINGS"},
    )
    assert "PS_PUBLIC_STRINGS" in s


def test_guid_invalid_short():
    assert "invalid" in guid(b"\x00\x01")


# --------------------------------------------------------------------------- #
# EntryID  ([MS-OXCDATA] §2.2.4; PLAN §9.4, Appendix A H18)
# --------------------------------------------------------------------------- #
def test_entryid_one_off_smtp():
    # One-off EntryID: abFlags[0]=0x01, one-off MAPIUID, flags=Unicode,
    # then DisplayName / AddressType / EmailAddress null-terminated UTF-16LE.
    ab_flags = bytes([0x01, 0x00, 0x00, 0x00])
    uid = bytes.fromhex("812b1fa4bea310199d6e00dd010f5402")  # one-off provider
    version = struct.pack("<H", 0)
    flags = struct.pack("<H", 0x8000)  # MAE_UNICODE

    def u16z(s: str) -> bytes:
        return s.encode("utf-16-le") + b"\x00\x00"

    body = u16z("Jane Doe") + u16z("SMTP") + u16z("jane@example.com")
    blob = ab_flags + uid + version + flags + body
    out = entryid(blob)
    assert out["type"] == "one-off"
    assert out["display"] == "Jane Doe"
    assert out["addrtype"] == "SMTP"
    assert out["email"] == "jane@example.com"
    assert out["smtp"] == "jane@example.com"


def test_entryid_addressbook_x500():
    ab_flags = bytes(4)
    uid = bytes.fromhex("dca740c8c042101ab4b908002b2fe182")  # AB provider
    version = struct.pack("<I", 1)
    abtype = struct.pack("<I", 0)  # local mail user
    dn = b"/O=ORG/OU=EXCHANGE/CN=RECIPIENTS/CN=JDOE\x00"
    blob = ab_flags + uid + version + abtype + dn
    out = entryid(blob)
    assert out["type"] == "address-book"
    assert out["x500"].startswith("/O=ORG")


def test_entryid_store_no_smtp():
    # Store/object EntryID does NOT yield an address (Appendix A H18).
    ab_flags = bytes(4)
    uid = bytes.fromhex("38a1bb1005e5101aa1bb08002b2a56c2")  # arbitrary store UID
    provider = uid  # store UID + (truncated) -> classified store-or-object
    blob = ab_flags + uid + provider
    out = entryid(blob)
    assert "smtp" not in out
    assert out["type"] in ("store", "store-or-object", "folder", "message")


def test_entryid_truncated():
    assert entryid(b"\x01\x00")["type"] == "truncated"


# --------------------------------------------------------------------------- #
# LZFu / compressed RTF  ([MS-OXRTFCP] §2.1.3; PLAN §9.5, Appendix A H10)
# --------------------------------------------------------------------------- #
def test_rtf_init_dict_length():
    # Locked length from [MS-OXRTFCP] §2.1.3.1.2.
    assert len(_INIT_DICT) == RTF_INIT_DICT_LEN == 207


def _build_lzfu(plaintext: bytes, tokens: list) -> bytes:
    """Assemble an LZFu stream from a token list (literals/refs) and header.

    tokens: list of either ('lit', byte) or ('ref', offset, length).
    Returns the full blob (16B header + compressed data) with a valid CRC.
    """
    comp = bytearray()
    pending = []  # collected (is_ref, payload-bytes)
    flat = []
    for t in tokens:
        if t[0] == "lit":
            flat.append((0, bytes([t[1]])))
        else:
            _, off, length = t
            token = ((off & 0x0FFF) << 4) | ((length - 2) & 0x0F)
            flat.append((1, struct.pack(">H", token)))
    # Pack into control-byte groups of 8.
    i = 0
    while i < len(flat):
        group = flat[i:i + 8]
        control = 0
        for bit, (is_ref, _payload) in enumerate(group):
            if is_ref:
                control |= 1 << bit
        comp.append(control)
        for _is_ref, payload in group:
            comp += payload
        i += 8
    comp = bytes(comp)
    crc = compute_crc(comp)
    # [MS-OXRTFCP] §2.1.3.1.1: COMPSIZE = size of everything after the COMPSIZE
    # field == RAWSIZE(4)+COMPTYPE(4)+CRC(4)+compressed == 12 + len(comp), so
    # COMPSIZE+4 == total file size and the data spans [16, COMPSIZE+4).
    comp_size = len(comp) + 12
    header = struct.pack("<IIII", comp_size, len(plaintext), 0x75465A4C, crc)
    return header + comp


def test_rtf_literal_roundtrip():
    plain = b"Hi!"
    tokens = [("lit", c) for c in plain]
    blob = _build_lzfu(plain, tokens)
    sink = WarningSink()
    assert decompress_rtf(blob, sink) == plain
    assert WarnCode.RTF_CRC_FAIL not in sink.codes()


def test_rtf_backreference_into_static_dict():
    # The decisive case (Appendix A H10): a back-reference that reads from the
    # PRE-SEEDED static dictionary, before any literal has been emitted.
    # _INIT_DICT starts with "{\\rtf1\\ansi\\mac..." — offset 0, length 6 yields
    # the first 6 bytes of the static dict: b"{\\rtf1".
    expect = _INIT_DICT[0:6]
    tokens = [("ref", 0, 6)]
    blob = _build_lzfu(expect, tokens)
    out = decompress_rtf(blob, WarningSink())
    assert out == expect == b"{\\rtf1"


def test_rtf_backref_then_literal():
    # ref into static dict ("{\\rtf1") followed by a literal '}'.
    head = _INIT_DICT[0:6]
    plain = head + b"}"
    tokens = [("ref", 0, 6), ("lit", ord("}"))]
    blob = _build_lzfu(plain, tokens)
    assert decompress_rtf(blob, WarningSink()) == plain


def test_rtf_uncompressed_mela():
    raw = b"{\\rtf1 plain}"
    header = struct.pack("<IIII", len(raw) + 8, len(raw), 0x414C454D, 0)
    assert decompress_rtf(header + raw) == raw


def test_rtf_crc_fail_best_effort():
    plain = b"AB"
    blob = bytearray(_build_lzfu(plain, [("lit", 65), ("lit", 66)]))
    # Corrupt the stored CRC (offset 12..16).
    blob[12] ^= 0xFF
    sink = WarningSink()
    out = decompress_rtf(bytes(blob), sink)
    assert out == plain  # best-effort still decodes
    assert WarnCode.RTF_CRC_FAIL in sink.codes()


# --------------------------------------------------------------------------- #
# Conversation index  ([MS-OXOMSG] §2.2.1.3; PLAN §9.6, Appendix A H16)
# --------------------------------------------------------------------------- #
def test_conversation_index_header_time_from_filetime():
    # Build header from a known FILETIME: take a real FILETIME, keep its high 40
    # bits (FILETIME >> 24), store big-endian as 5 bytes.
    dt = datetime(2020, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
    ft = int((dt - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1e7)
    header40 = ft >> 24
    blob = bytes([0x01]) + header40.to_bytes(5, "big") + bytes.fromhex(
        "0102030405060708090a0b0c0d0e0f10"
    )
    out = conversation_index(blob)
    assert out["corrupt"] is False
    assert out["guid"] == "04030201-0605-0807-090a-0b0c0d0e0f10"
    # header_filetime reconstructed == header40 << 24; rendered time is within
    # the 24-bit (≈1.67 s) truncation window of the original.
    assert out["header_filetime"] == header40 << 24
    parsed = datetime.fromisoformat(out["header_time"])
    assert abs((parsed - dt).total_seconds()) < 2.0


def test_conversation_index_children_count():
    base = bytes([0x01]) + (0).to_bytes(5, "big") + bytes(16)
    child = bytes([0x00, 0x00, 0x10, 0x00, 0x00])  # one child block
    out = conversation_index(base + child)
    assert len(out["children"]) == 1
    assert out["children"][0]["filetime"] >= 0


def test_conversation_index_corrupt_length():
    out = conversation_index(bytes(22) + b"\x01\x02")  # 2 trailing bytes
    assert out["corrupt"] is True


def test_conversation_index_unverified_warn():
    sink = WarningSink()
    base = bytes([0x01]) + (0).to_bytes(5, "big") + bytes(16) + bytes(5)
    conversation_index(base, sink=sink)
    assert WarnCode.UNVERIFIED_CONST in sink.codes()


# --------------------------------------------------------------------------- #
# Strings  (PLAN §9.7, Appendix A H19)
# --------------------------------------------------------------------------- #
def test_decode_unicode():
    raw = "Grüße".encode("utf-16-le")
    assert decode_string(raw, PropType.STRING) == "Grüße"


def test_decode_unicode_strips_bom():
    raw = b"\xff\xfe" + "Hi".encode("utf-16-le")
    assert decode_string(raw, PropType.STRING) == "Hi"


def test_decode_string8_default_1252():
    raw = "café".encode("cp1252")
    assert decode_string(raw, PropType.STRING8) == "café"


def test_decode_string8_utf8_cp():
    raw = "日本".encode("utf-8")
    assert decode_string(raw, PropType.STRING8, codepage=65001) == "日本"


def test_decode_string8_shift_jis():
    raw = "日本".encode("shift_jis")
    assert decode_string(raw, PropType.STRING8, codepage=932) == "日本"


# --------------------------------------------------------------------------- #
# Other typed decoders  (PLAN §9.8, Appendix A H11)
# --------------------------------------------------------------------------- #
def test_currency_scaled_10000():
    # 123400 / 10000 == 12.3400 (4 decimals, no symbol).
    assert render_currency(struct.pack("<q", 123400)) == "12.3400"
    assert render_currency(struct.pack("<q", -5)) == "-0.0005"


# --------------------------------------------------------------------------- #
# Dispatcher + install_renderer
# --------------------------------------------------------------------------- #
def test_render_value_dispatch_time_and_int():
    obj = MapiObject()
    dt = datetime(2009, 7, 14, 12, 0, 0, tzinfo=timezone.utc)
    obj.add(MapiValue(make_tag(0x0039, PropType.TIME), _ft_bytes(dt)))  # ClientSubmitTime
    obj.add(MapiValue(make_tag(0x0E08, PropType.INTEGER32), struct.pack("<i", 4242)))
    assert render_value(obj, make_tag(0x0039, PropType.TIME)) == dt
    assert render_value(obj, make_tag(0x0E08, PropType.INTEGER32)) == 4242


def test_render_value_string_records_encoding():
    obj = MapiObject()
    tag = make_tag(0x0037, PropType.STRING8)
    obj.add(MapiValue(tag, "abc".encode("cp1252")))
    assert render_value(obj, tag) == "abc"
    assert obj.get_tag(tag).encoding == "cp1252"


def test_render_value_multivalue_strings():
    obj = MapiObject()
    tag = make_tag(0x1234, PropType.MV_STRING)
    v = MapiValue(tag, b"", elements=["a".encode("utf-16-le"), "bb".encode("utf-16-le")])
    obj.add(v)
    assert render_value(obj, tag) == ["a", "bb"]


def test_install_renderer_wires_render():
    obj = MapiObject()
    tag = make_tag(0x0E08, PropType.INTEGER32)
    obj.add(MapiValue(tag, struct.pack("<i", 7)))
    install_renderer(obj)
    assert obj.render(tag) == 7


def test_render_value_absent_tag():
    obj = MapiObject()
    assert render_value(obj, make_tag(0x9999, PropType.INTEGER32)) is None
