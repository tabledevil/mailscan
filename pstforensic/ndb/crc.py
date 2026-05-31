"""MS-PST CRC and block/page signature ([MS-PST] §5.3, §5.5).

VERIFIED (PLAN Appendix A H3/H4):
  * The CRC is **standard CRC-32, reflected polynomial 0xEDB88320**, but with
    **seed 0 and NO pre/post inversion** (unlike zlib's 0xFFFFFFFF init + final
    XOR). The spec ships a slicing-by-8 form; CrcTableOffset32 is exactly the
    standard CRC-32 table. We build the table from the polynomial and lock it
    against spec anchor values + an independent bitwise oracle (see tests).
    (gemini's "CRC-32C / 0x1EDC6F41" review claim was verified WRONG.)
  * ``compute_sig(ib, bid)`` is the simple XOR-fold of §5.5, NOT a CRC-16.
"""
from __future__ import annotations

POLY = 0xEDB88320  # reflected CRC-32 polynomial


def _build_table() -> list[int]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ POLY if (c & 1) else (c >> 1)
        table.append(c & 0xFFFFFFFF)
    return table


_CRC_TABLE = _build_table()

# Spec anchors from [MS-PST] §5.3 CrcTableOffset32 — guards against a corrupted
# table (and documents the verified ground truth inline).
_SPEC_ANCHORS = {
    1: 0x77073096,
    2: 0xEE0E612C,
    8: 0x0EDB8832,
    128: 0xEDB88320,
    255: 0x2D02EF8D,
}
for _i, _v in _SPEC_ANCHORS.items():
    assert _CRC_TABLE[_i] == _v, f"CRC table anchor {_i} mismatch: {_CRC_TABLE[_i]:#x} != {_v:#x}"


def compute_crc(data: bytes, seed: int = 0) -> int:
    """MS-PST CRC-32 (seed 0, no inversion) over ``data``.

    ``seed`` defaults to 0 per the spec (the optional dwCRC argument). No final
    inversion is applied — the running value is returned directly.
    """
    crc = seed & 0xFFFFFFFF
    table = _CRC_TABLE
    for b in data:
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc & 0xFFFFFFFF


def compute_crc_bitwise(data: bytes, seed: int = 0) -> int:
    """Independent bit-level reference of the same algorithm (test oracle).

    Implemented from the polynomial directly (no table) so the table-driven
    :func:`compute_crc` can be locked against an algorithmically-distinct path.
    """
    crc = seed & 0xFFFFFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ POLY if (crc & 1) else (crc >> 1)
    return crc & 0xFFFFFFFF


def compute_sig(ib: int, bid: int) -> int:
    """Block/page signature wSig ([MS-PST] §5.5).

    ``ComputeSig(ib, bid) = WORD((x >> 16) ^ x)`` where ``x = ib ^ bid``.
    (gemini's "CRC-16 over page data" review claim was verified WRONG.)
    """
    x = (ib ^ bid) & 0xFFFFFFFF
    return ((x >> 16) ^ x) & 0xFFFF
