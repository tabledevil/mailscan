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
from .. import integrity as I
from ..integrity import Integrity
from ..variant import (
    ALL_VARIANTS,
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
    integrity: Integrity = None  # store-level header findings (PLAN §14.3)
    magic_ok: bool = True
    # Variants whose NBT root page validates under their geometry:
    # name -> "verified" (sig+CRC too) | "consistent" (ptype+geometry only).
    variant_evidence: dict = None


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


def _root_evidence(reader: FileReader, variant: Variant) -> str | None:
    """Does the NBT root page under ``variant``'s geometry look real?

    Returns ``"verified"`` (ptype+geometry+sig+CRC), ``"consistent"``
    (ptype+geometry — Kernel's gate) or ``None``.
    """
    from .btree import PTYPE_NBT, verify_page  # local: btree imports header deps
    raw = reader.read_exact(variant.root_offset, variant.root_size, where="ROOT probe")
    if raw is None:
        return None
    o = 4 + 4 * variant.bid_size  # dwReserved + 4 size fields
    bref = parse_bref(raw, o, variant.bid_size)
    if not (0 < bref.ib and bref.ib + variant.page_size <= reader.size):
        return None
    page = reader.read_exact(bref.ib, variant.page_size, where="ROOT probe")
    if page is None:
        return None
    v = verify_page(page, bref.ib, PTYPE_NBT, variant, bref_bid=bref.raw_bid)
    if not (v.ptype_ok and v.geometry_ok):
        return None
    return I.VERIFIED if (v.crc_ok and v.sig_ok and v.bid_ok) else I.CONSISTENT


def detect(reader: FileReader, *, sink: WarningSink | None = None) -> Header:
    """Detect + parse the store header and ROOT ([MS-PST] §2.2.2.6).

    Tolerant (PLAN §14.2): a bad ``!BDN`` magic, bad client magic, header CRC
    mismatch or an unknown/wrong ``wVer`` are *findings*, not errors.  Every
    variant is tried against the NBT root page; the one(s) whose geometry
    validates are recorded in ``variant_evidence``.

    Raises :class:`NotAPstError` only if the magic is wrong **and** no variant
    validates, :class:`UnsupportedStoreError` if the magic is right but no
    variant can be resolved, and :class:`EncryptedStoreError` for
    ``bCryptMethod == 0x10`` (WIP/EDP).
    """
    # An empty WarningSink is falsy (__len__ == 0); use an explicit None check.
    sink = sink if sink is not None else reader.sink
    integ = Integrity()

    magic = reader.read(OFF_MAGIC, 4, where="header")
    magic_ok = magic == MAGIC
    if not magic_ok:
        integ.add(I.HEADER_MAGIC_BAD, f"{magic!r}", ib=OFF_MAGIC)
        sink.warn(WarnCode.SIG_MISMATCH, f"bad magic {magic!r}", where="header")

    client = reader.read(OFF_MAGIC_CLIENT, 2, where="header")
    if client != MAGIC_CLIENT:
        integ.add(I.HEADER_CLIENT_MAGIC_BAD, f"{client!r}", ib=OFF_MAGIC_CLIENT)
        sink.warn(WarnCode.SIG_MISMATCH,
                  f"wMagicClient {client!r} != {MAGIC_CLIENT!r}", where="header")

    wver = reader.u16(OFF_WVER)
    if wver not in (14, 15, 21, 23, 36, 37):
        integ.add(I.WVER_UNUSUAL, f"wVer={wver}", ib=OFF_WVER)
    try:
        declared: Variant | None = classify(wver)
    except ValueError:
        declared = None

    evidence = {v.name: lv for v in ALL_VARIANTS
                if (lv := _root_evidence(reader, v)) is not None}
    by_name = {v.name: v for v in ALL_VARIANTS}

    if declared is not None and (declared.name in evidence or not evidence):
        variant = declared
    elif evidence:
        # Header disagrees with (or cannot name) the geometry the file has:
        # prefer the strongest evidence, flag the override.
        best = sorted(evidence, key=lambda n: I.LEVELS.index(evidence[n]))[0]
        variant = by_name[best]
        integ.add(I.VARIANT_FROM_EVIDENCE,
                  f"wVer={wver} declares {declared.name if declared else 'nothing'}; "
                  f"root page validates as {best}")
    else:
        if not magic_ok:
            raise NotAPstError(f"bad magic {magic!r} and no variant validates")
        raise UnsupportedStoreError(f"unrecognised wVer={wver}; no variant validates")
    if not magic_ok and not evidence:
        raise NotAPstError(f"bad magic {magic!r}, expected {MAGIC!r}")

    if not variant.verified:
        sink.warn(WarnCode.UNVERIFIED_CONST,
                  f"wVer={wver} 4K-OST geometry is a working hypothesis "
                  "(PLAN Appendix A H20)", where="header")

    crypt_method = reader.u8(variant.crypt_method_offset)
    if crypt_method == CRYPT_EDPCRYPTED:
        raise EncryptedStoreError(
            f"bCryptMethod=0x10 (WIP/EDP) at offset {variant.crypt_method_offset:#x}")
    if crypt_method not in (0, 1, 2):
        integ.add(I.CRYPT_METHOD_UNKNOWN, f"bCryptMethod={crypt_method:#x}",
                  ib=variant.crypt_method_offset)

    root_bytes = reader.read(variant.root_offset, variant.root_size, where="ROOT")
    root = _parse_root(root_bytes, variant, sink)
    if root.f_amap_valid == 0:
        integ.add(I.AMAP_INVALID, "fAMapValid=0")
    if root.ib_file_eof != reader.size:
        integ.add(I.EOF_MISMATCH,
                  f"ibFileEof={root.ib_file_eof:#x} file size={reader.size:#x}")

    # --- Advisory CRC checks (never abort — AC-4) ---
    crc_partial_ok = _check_crc_partial(reader, sink)
    crc_full_ok = _check_crc_full(reader, variant, sink)
    if not crc_partial_ok:
        integ.add(I.HEADER_CRC_FAIL, "dwCRCPartial", ib=OFF_CRC_PARTIAL)
    if crc_full_ok is False:
        integ.add(I.HEADER_CRC_FAIL, "dwCRCFull", ib=OFF_CRC_FULL_UNICODE)

    return Header(
        variant=variant,
        wver=wver,
        crypt_method=crypt_method,
        root=root,
        wip_capable=wver_is_wip_capable(wver),
        crc_partial_ok=crc_partial_ok,
        crc_full_ok=crc_full_ok,
        integrity=integ,
        magic_ok=magic_ok,
        variant_evidence=evidence,
    )


def headerless(reader: FileReader, cause: Exception, *,
               sink: WarningSink | None = None) -> Header:
    """A stand-in header for a store whose header is unusable (PLAN §14.2).

    The variant is the one under whose geometry the full-file scan finds the
    most NBT pages; the crypt method is left unknown for the crypt ladder; the
    ROOT points nowhere, so every node is resolved from the scan.  Raises
    ``cause`` again if the file holds no B-tree page under any variant.
    """
    from .scan import scan_file
    from ..variant import UNICODE
    probe = scan_file(reader, UNICODE)
    counts: dict[str, int] = {}
    for p in probe.pages:
        if p.ptype == 0x81:
            counts[p.variant] = counts.get(p.variant, 0) + 1
    if not counts:
        raise cause
    by_name = {v.name: v for v in ALL_VARIANTS}
    best = max(counts, key=lambda n: counts[n])
    variant = by_name[best]
    integ = Integrity()
    integ.add(I.HEADER_UNUSABLE, str(cause))
    integ.add(I.VARIANT_FROM_EVIDENCE,
              f"{counts[best]} NBT pages validate as {best} (scan)")
    integ.add(I.CRYPT_METHOD_UNKNOWN, "header unusable; crypt ladder decides")
    nowhere = BREF(bid=0, ib=0, raw_bid=0)
    root = Root(ib_file_eof=reader.size, ib_amap_last=0, cb_amap_free=0,
                cb_pmap_free=0, bref_nbt=nowhere, bref_bbt=nowhere, f_amap_valid=0)
    return Header(variant=variant, wver=reader.u16(OFF_WVER), crypt_method=0xFF,
                  root=root, wip_capable=False, crc_partial_ok=False,
                  crc_full_ok=None if not variant.is_unicode else False,
                  integrity=integ, magic_ok=reader.read(OFF_MAGIC, 4) == MAGIC,
                  variant_evidence={best: I.CONSISTENT})


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
