"""Lock the MS-PST CRC and signature against ground truth.

These are *test-vector locks* per PLAN §0.5: the table-driven CRC is checked
against (a) an independent bitwise implementation and (b) literal spec anchor
values, so the constant cannot silently drift.
"""
import os
import zlib

import pytest

from pstforensic.ndb.crc import (
    POLY,
    _CRC_TABLE,
    compute_crc,
    compute_crc_bitwise,
    compute_sig,
)


def test_poly_is_reflected_crc32():
    assert POLY == 0xEDB88320


@pytest.mark.parametrize("idx,expected", [
    (0, 0x00000000),
    (1, 0x77073096),
    (2, 0xEE0E612C),
    (8, 0x0EDB8832),
    (128, 0xEDB88320),
    (255, 0x2D02EF8D),
])
def test_spec_table_anchors(idx, expected):
    # Anchor values quoted from [MS-PST] §5.3 CrcTableOffset32.
    assert _CRC_TABLE[idx] == expected


@pytest.mark.parametrize("data", [
    b"",
    b"\x00",
    b"SM",
    b"!BDN",
    b"The quick brown fox jumps over the lazy dog",
    bytes(range(256)),
    os.urandom(1000),
])
def test_table_matches_bitwise(data):
    # Independent algorithm (bitwise) must agree with the fast table path.
    assert compute_crc(data) == compute_crc_bitwise(data)


def test_seed_zero_no_inversion_differs_from_zlib():
    # MS-PST uses seed 0 and NO pre/post inversion; zlib uses 0xFFFFFFFF init +
    # final XOR. They MUST differ for non-empty input — this guards against
    # accidentally re-implementing zlib's variant.
    data = b"hello world"
    assert compute_crc(data) != (zlib.crc32(data) & 0xFFFFFFFF)
    # And the empty string is 0 under MS-PST (seed, no inversion).
    assert compute_crc(b"") == 0


def test_crc_is_deterministic_and_bounded():
    v = compute_crc(b"forensic")
    assert 0 <= v <= 0xFFFFFFFF
    assert compute_crc(b"forensic") == v


def test_compute_sig_xorfold():
    # [MS-PST] §5.5: ComputeSig(ib,bid) = WORD((x>>16) ^ x), x = ib ^ bid.
    assert compute_sig(0, 0) == 0
    ib, bid = 0x0001A2B0, 0x0000004C
    x = ib ^ bid
    assert compute_sig(ib, bid) == (((x >> 16) ^ x) & 0xFFFF)
    # Result always fits in 16 bits.
    assert 0 <= compute_sig(0x12345678, 0x9ABCDEF0) <= 0xFFFF
