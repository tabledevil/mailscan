"""Lock the foundation contracts: variant geometry, proptypes, fileio, model."""
import pytest

import pstforensic as pf
from pstforensic import proptypes as pt
from pstforensic import variant as V
from pstforensic.fileio import FileReader
from pstforensic.mapi import MapiMessage, MapiValue


# --- variant geometry (PLAN Appendix A spec-verified offsets) --------------
def test_ansi_header_offsets():
    assert V.ANSI.root_offset == 0x00A4
    assert V.ANSI.root_size == 40
    assert V.ANSI.crypt_method_offset == 0x01CD
    assert V.ANSI.bid_size == 4 and V.ANSI.bref_size == 8
    assert V.ANSI.block_trailer_size == 12


def test_unicode_header_offsets():
    assert V.UNICODE.root_offset == 0x00B4
    assert V.UNICODE.root_size == 72
    assert V.UNICODE.crypt_method_offset == 0x0201
    assert V.UNICODE.bid_size == 8 and V.UNICODE.bref_size == 16
    assert V.UNICODE.block_trailer_size == 16


def test_4k_is_marked_unverified():
    assert V.UNICODE_4K.page_size == 4096
    assert V.UNICODE_4K.verified is False


@pytest.mark.parametrize("wver,name", [
    (14, "ansi"), (15, "ansi"), (23, "unicode"), (35, "unicode"),
    (36, "unicode4k"), (37, "unicode4k"),
])
def test_classify(wver, name):
    assert V.classify(wver).name == name


def test_classify_rejects_unknown():
    with pytest.raises(ValueError):
        V.classify(2)


def test_wver37_is_wip_capable():
    assert V.wver_is_wip_capable(37) is True
    assert V.wver_is_wip_capable(36) is False


# --- proptypes -------------------------------------------------------------
def test_inline_only_4_bytes():
    # PLAN Appendix A H5: PST PC holds only 4 inline bytes.
    assert pt.is_inline_in_pc(pt.PropType.INTEGER32) is True   # 4B
    assert pt.is_inline_in_pc(pt.PropType.BOOLEAN) is True     # 1B
    assert pt.is_inline_in_pc(pt.PropType.INTEGER64) is False  # 8B
    assert pt.is_inline_in_pc(pt.PropType.TIME) is False       # 8B FILETIME
    assert pt.is_inline_in_pc(pt.PropType.GUID) is False       # 16B
    assert pt.is_inline_in_pc(pt.PropType.STRING) is False     # variable


def test_mv_flag_and_base():
    assert pt.is_multivalue(pt.PropType.MV_STRING)
    assert not pt.is_multivalue(pt.PropType.STRING)
    assert pt.base_type(pt.PropType.MV_BINARY) == pt.PropType.BINARY


def test_tag_roundtrip():
    tag = pt.make_tag(0x0037, 0x001F)  # PidTagSubject (Unicode)
    assert pt.split_tag(tag) == (0x0037, 0x001F)
    assert pt.tag_str(tag) == "0x0037001F"


# --- fileio bounds guard ---------------------------------------------------
def test_reader_clamps_out_of_bounds():
    r = FileReader(b"\x01\x02\x03\x04")
    assert r.size == 4
    assert r.u16(0) == 0x0201
    assert r.u32(0) == 0x04030201
    # Over-read returns what exists and records a warning, never raises.
    assert r.read(2, 100) == b"\x03\x04"
    assert r.read(99, 4) == b""
    assert any(w.code == pf.WarnCode.OUT_OF_BOUNDS for w in r.sink.warnings)


def test_read_exact_none_on_short():
    r = FileReader(b"ab")
    assert r.read_exact(0, 2) == b"ab"
    assert r.read_exact(0, 3) is None


# --- model -----------------------------------------------------------------
def test_mapi_object_property_access():
    m = MapiMessage()
    m.add(MapiValue(tag=pt.make_tag(0x0037, 0x001F), raw=b"S\x00u\x00b\x00"))
    assert m.has(0x0037)
    assert m.by_id(0x0037).raw == b"S\x00u\x00b\x00"
    assert len(m) == 1
    assert m.by_id(0x9999) is None
