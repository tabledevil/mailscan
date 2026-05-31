"""HEADER + ROOT parsing ([MS-PST] §2.2.2.6).

All offsets are the spec-verified ones from PLAN Appendix A.2 (the dossier and
both adversarial reviewers were each wrong about these — never hand-edit a
constant here without a locking test).

Layout (Appendix A.2):
  dwMagic       @0x0000  4   "!BDN"
  dwCRCPartial  @0x0004  4   CRC of 471 bytes from 0x0008
  wMagicClient  @0x0008  2   "SM"
  wVer          @0x000A  2   14/15=ANSI, >=23=Unicode, 36/37=4K
  ROOT          @0x00A4 (ANSI,40B) / @0x00B4 (Unicode,72B)
  bCryptMethod  @0x01CD (ANSI) / @0x0201 (Unicode)
  dwCRCFull     @0x020C  4   Unicode only; CRC of 516 bytes 0x0008..bidNextB

ROOT structure ([MS-PST] §2.2.2.6.1):
  Unicode (72B): dwReserved(4) ibFileEof(8) ibAMapLast(8) cbAMapFree(8)
                 cbPMapFree(8) BREFNBT(16) BREFBBT(16) fAMapValid(1)
                 bReserved(1) wReserved(2)
  ANSI   (40B): dwReserved(4) ibFileEof(4) ibAMapLast(4) cbAMapFree(4)
                 cbPMapFree(4) BREFNBT(8) BREFBBT(8) fAMapValid(1)
                 bReserved(1) wReserved(2)
"""
from __future__ import annotations

from dataclasses import dataclass

from ..exceptions import (
    EncryptedStoreError,
    NotAPstError,
    UnsupportedStoreError,
    WarnCode,
    WarningSink,
)
from ..fileio import FileReader
from ..variant import (
    CRYPT_EDPCRYPTED,
    MAGIC,
    MAGIC_CLIENT,
    Variant,
    classify,
    wver_is_wip_capable,
)
from .bref import BREF, parse_bref
from .crc import compute_crc

# Header field offsets shared by all variants ([MS-PST] §2.2.2.6 / Appendix A.2).
OFF_MAGIC = 0x0000
OFF_CRC_PARTIAL = 0x0004
OFF_MAGIC_CLIENT = 0x0008
OFF_WVER = 0x000A
OFF_WVER_CLIENT = 0x000C

# dwCRCPartial covers 471 bytes starting at 0x0008 ([MS-PST] §2.2.2.6 / A.2).
CRC_PARTIAL_START = 0x0008
CRC_PARTIAL_LEN = 471
# dwCRCFull (Unicode only) covers 516 bytes from 0x0008 up to bidNextB.
OFF_CRC_FULL_UNICODE = 0x020C
CRC_FULL_LEN = 516

# fAMapValid sentinel meaning "valid" ([MS-PST] §2.2.2.6.1): INVALID_AMAP=0,
# VALID_AMAP1=1, VALID_AMAP2=2.  We accept any non-zero as "claims valid" but
# the canonical "fully valid" value used by recent Outlook is 2.
AMAP_VALID2 = 0x02


@dataclass
class Root:
    """Parsed ROOT block ([MS-PST] §2.2.2.6.1)."""

    ib_file_eof: int
    ib_amap_last: int
    cb_amap_free: int
    cb_pmap_free: int
    bref_nbt: BREF
    bref_bbt: BREF
    f_amap_valid: int


@dataclass
class Header:
    """Parsed PST/OST header + ROOT, with the resolved :class:`Variant`."""

    variant: Variant
    wver: int
    crypt_method: int
    root: Root
    wip_capable: bool
    crc_partial_ok: bool
    crc_full_ok: bool | None  # None for ANSI (no dwCRCFull)


def _parse_root(buf: bytes, variant: Variant, sink: WarningSink) -> Root:
    """Parse the ROOT structure from ``buf`` (the ROOT bytes) ([MS-PST] §2.2.2.6.1)."""
    w = variant.bid_size  # 4 (ANSI) or 8 (Unicode)
    o = 4  # skip dwReserved(4)

    def rd(n: int) -> int:
        nonlocal o
        v = int.from_bytes(buf[o:o + n], "little")
        o += n
        return v

    ib_file_eof = rd(w)
    ib_amap_last = rd(w)
    cb_amap_free = rd(w)
    cb_pmap_free = rd(w)
    bref_nbt = parse_bref(buf, o, variant.bid_size); o += variant.bref_size
    bref_bbt = parse_bref(buf, o, variant.bid_size); o += variant.bref_size
    f_amap_valid = buf[o] if o < len(buf) else 0

    if f_amap_valid == 0:
        sink.warn(WarnCode.AMAP_INVALID, f"fAMapValid={f_amap_valid}", where="ROOT")
    return Root(
        ib_file_eof=ib_file_eof,
        ib_amap_last=ib_amap_last,
        cb_amap_free=cb_amap_free,
        cb_pmap_free=cb_pmap_free,
        bref_nbt=bref_nbt,
        bref_bbt=bref_bbt,
        f_amap_valid=f_amap_valid,
    )


def detect(reader: FileReader, *, sink: WarningSink | None = None) -> Header:
    """Detect + parse the store header and ROOT ([MS-PST] §2.2.2.6).

    Raises :class:`NotAPstError` if the ``!BDN`` magic is absent,
    :class:`EncryptedStoreError` if ``bCryptMethod == 0x10`` (WIP/EDP), and
    :class:`UnsupportedStoreError` for an unrecognisable ``wVer``.  Every other
    anomaly (bad client magic, CRC mismatch, invalid AMap) is a warning so the
    recovery engine can still proceed.
    """
    # An empty WarningSink is falsy (__len__ == 0); use an explicit None check.
    sink = sink if sink is not None else reader.sink

    magic = reader.read(OFF_MAGIC, 4, where="header")
    if magic != MAGIC:
        raise NotAPstError(f"bad magic {magic!r}, expected {MAGIC!r}")

    client = reader.read(OFF_MAGIC_CLIENT, 2, where="header")
    if client != MAGIC_CLIENT:
        sink.warn(WarnCode.SIG_MISMATCH,
                  f"wMagicClient {client!r} != {MAGIC_CLIENT!r}", where="header")

    wver = reader.u16(OFF_WVER)
    try:
        variant = classify(wver)
    except ValueError as exc:
        raise UnsupportedStoreError(str(exc)) from exc

    if not variant.verified:
        sink.warn(WarnCode.UNVERIFIED_CONST,
                  f"wVer={wver} 4K-OST geometry is a working hypothesis "
                  "(PLAN Appendix A H20)", where="header")

    crypt_method = reader.u8(variant.crypt_method_offset)
    if crypt_method == CRYPT_EDPCRYPTED:
        raise EncryptedStoreError(
            f"bCryptMethod=0x10 (WIP/EDP) at offset {variant.crypt_method_offset:#x}")

    root_bytes = reader.read(variant.root_offset, variant.root_size, where="ROOT")
    root = _parse_root(root_bytes, variant, sink)

    # --- Advisory CRC checks (never abort — AC-4) ---
    crc_partial_ok = _check_crc_partial(reader, sink)
    crc_full_ok = _check_crc_full(reader, variant, sink)

    return Header(
        variant=variant,
        wver=wver,
        crypt_method=crypt_method,
        root=root,
        wip_capable=wver_is_wip_capable(wver),
        crc_partial_ok=crc_partial_ok,
        crc_full_ok=crc_full_ok,
    )


def _check_crc_partial(reader: FileReader, sink: WarningSink) -> bool:
    """Verify dwCRCPartial (471 bytes @0x0008) — advisory ([MS-PST] §2.2.2.6)."""
    stored = reader.u32(OFF_CRC_PARTIAL)
    body = reader.read(CRC_PARTIAL_START, CRC_PARTIAL_LEN, where="dwCRCPartial")
    if len(body) != CRC_PARTIAL_LEN:
        return False
    calc = compute_crc(body)
    ok = calc == stored
    if not ok:
        sink.warn(WarnCode.HEADER_CRC_FAIL,
                  f"dwCRCPartial stored={stored:#010x} calc={calc:#010x}",
                  where="header")
    return ok


def _check_crc_full(reader: FileReader, variant: Variant, sink: WarningSink) -> bool | None:
    """Verify dwCRCFull (516 bytes, Unicode only) — advisory ([MS-PST] §2.2.2.6)."""
    if not variant.is_unicode:
        return None
    stored = reader.u32(OFF_CRC_FULL_UNICODE)
    body = reader.read(CRC_PARTIAL_START, CRC_FULL_LEN, where="dwCRCFull")
    if len(body) != CRC_FULL_LEN:
        return False
    calc = compute_crc(body)
    ok = calc == stored
    if not ok:
        sink.warn(WarnCode.HEADER_CRC_FAIL,
                  f"dwCRCFull stored={stored:#010x} calc={calc:#010x}",
                  where="header")
    return ok
