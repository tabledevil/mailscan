"""Lock tools/fingerprint.py (content-free triage) against the synth oracle
and against pstforensic's own header/CRC code, so the two can't drift."""
from __future__ import annotations

import pytest

from pstforensic.fileio import FileReader
from pstforensic.ndb.crc import compute_crc
from pstforensic.ndb.header import detect
from pstforensic.tools.fingerprint import fingerprint, ms_crc
from pstforensic.variant import CRYPT_CYCLIC, CRYPT_NONE, CRYPT_PERMUTE

from .synth import build_ansi_pst, build_unicode_pst, build_unicode_pst_tree

MSGS = [{"subject": "a", "body": "b"}]


def _write(tmp_path, blob, name="s.pst"):
    p = tmp_path / name
    p.write_bytes(blob)
    return str(p)


def test_ms_crc_matches_library_crc():
    for data in (b"", b"\x00" * 471, bytes(range(256)) * 3):
        assert ms_crc(data) == compute_crc(data)


@pytest.mark.parametrize("builder,variant", [
    (lambda c: build_unicode_pst(messages=MSGS, crypt=c), "unicode"),
    (lambda c: build_ansi_pst(messages=MSGS, crypt=c), "ansi"),
])
@pytest.mark.parametrize("crypt,cname", [
    (CRYPT_NONE, "NONE"), (CRYPT_PERMUTE, "PERMUTE"), (CRYPT_CYCLIC, "CYCLIC")])
def test_fingerprint_clean_store(tmp_path, builder, variant, crypt, cname):
    blob = builder(crypt)
    fp = fingerprint(_write(tmp_path, blob), do_scan=True)
    hdr = detect(FileReader(blob))
    assert fp["variant"] == variant
    assert fp["wVer"] == hdr.wver
    assert fp["bCryptMethod"] == cname
    assert fp["crc_partial_ok"] is hdr.crc_partial_ok
    for key, bref in (("nbt_root", hdr.root.bref_nbt), ("bbt_root", hdr.root.bref_bbt)):
        r = fp[key]
        assert r["ib"] == bref.ib and r["in_file"]
        assert r["ptype_ok"] and r["trailer_bid_matches_bref"]
        assert r["crc_ok"] and r["sig_ok"]
    assert fp["scan"]["pages_with_valid_sig"]["BBT"]["seen"] >= 1
    assert fp["scan"]["pages_with_valid_sig"]["NBT"]["seen"] >= 1


def test_fingerprint_bad_header_crc(tmp_path):
    blob = build_unicode_pst(messages=MSGS, corrupt="bad_header_crc")
    fp = fingerprint(_write(tmp_path, blob))
    assert fp["crc_partial_ok"] is False


def test_fingerprint_truncated(tmp_path):
    blob = build_unicode_pst_tree(corrupt="truncate")
    fp = fingerprint(_write(tmp_path, blob))
    assert fp["root"]["eof_vs_size"] == "file_truncated"
    assert not (fp["nbt_root"]["in_file"] and fp["bbt_root"]["in_file"])


def test_fingerprint_emits_no_content(tmp_path):
    secret = "TOPSECRET-SUBJECT-4711"
    blob = build_unicode_pst(messages=[{"subject": secret, "body": secret}])
    text = repr(fingerprint(_write(tmp_path, blob), do_scan=True))
    assert secret not in text
