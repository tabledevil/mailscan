"""Compressed-RTF / LZFu decompression ([MS-OXRTFCP]; PLAN §9.5, Appendix A H10).

``PR_RTF_COMPRESSED (0x10090102)`` carries an RTF body compressed with the LZFu
scheme. Format (all little-endian header fields):

    COMPSIZE  u32   size of everything after this field (RAWSIZE+COMPTYPE+CRC
                    + compressed data == total file size - 4)
    RAWSIZE   u32   size of the uncompressed output
    MAGIC     u32   0x75465A4C 'LZFu' = compressed; 0x414C454D 'MELA' = stored
    CRC       u32   MS-PST CRC-32 (seed 0) over the compressed data bytes only

The decompressor maintains a 4096-byte **circular** dictionary, pre-seeded with
the exact static RTF prefix from [MS-OXRTFCP] §2.1.3.1.2 (embedded verbatim
below; its length is asserted at import). Each control byte holds 8 flags,
processed LSB-first: flag 0 => copy one literal byte; flag 1 => a 16-bit
**big-endian** reference = 12-bit dictionary offset + 4-bit length where the
real length is ``length + 2``. A reference whose offset equals the current write
position terminates the stream.

Pure, no I/O. CRC failure -> best-effort partial output + a ``RTF_CRC_FAIL``
warning (when a sink is supplied), per AC-6.
"""
from __future__ import annotations

import struct
from typing import Optional

from ..exceptions import WarnCode, WarningSink
from ..ndb.crc import compute_crc

# [MS-OXRTFCP] §2.1.3.1.2 — the exact static initialization dictionary. Embedded
# verbatim; do NOT "tidy" the whitespace. Its byte length MUST be 207.
_INIT_DICT = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}"
    b"{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript \\fdecor MS Sans SerifSymbolArial"
    b"Times New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n"
    b"\\par \\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)

# Lock the verified length (Appendix A H10 / [MS-OXRTFCP] §2.1.3.1.2).
RTF_INIT_DICT_LEN = 207
assert len(_INIT_DICT) == RTF_INIT_DICT_LEN, (
    f"LZFu init dictionary must be {RTF_INIT_DICT_LEN} bytes, got {len(_INIT_DICT)}"
)

_DICT_SIZE = 4096
_MAGIC_COMPRESSED = 0x75465A4C  # 'LZFu'
_MAGIC_UNCOMPRESSED = 0x414C454D  # 'MELA'


def decompress_rtf(b: bytes, sink: Optional[WarningSink] = None) -> bytes:
    """Decompress a ``PR_RTF_COMPRESSED`` blob to raw RTF bytes.

    :param b: the full compressed blob, including the 16-byte header.
    :param sink: optional :class:`WarningSink`; receives ``RTF_CRC_FAIL`` /
        ``COMPRESS_FAIL`` warnings instead of raising.
    :returns: the decompressed RTF bytes (best-effort on corruption).
    :raises ValueError: only if the header itself is too short to interpret.
    """
    if not isinstance(b, (bytes, bytearray)):
        raise ValueError("decompress_rtf expects bytes")
    b = bytes(b)
    if len(b) < 16:
        raise ValueError("compressed RTF shorter than 16-byte header")

    comp_size, raw_size, magic, crc = struct.unpack_from("<IIII", b, 0)

    if magic == _MAGIC_UNCOMPRESSED:
        # 'MELA': data after the header is stored verbatim, length RAWSIZE.
        return b[16:16 + raw_size]

    if magic != _MAGIC_COMPRESSED:
        if sink is not None:
            sink.warn(WarnCode.COMPRESS_FAIL,
                      f"unknown RTF magic 0x{magic:08X}", where="rtf")
        return b""

    # COMPSIZE counts MAGIC + CRC + compressed data == total length - 4.
    data_end = min(len(b), comp_size + 4)
    comp_data = b[16:data_end]

    # CRC is over the compressed data bytes only ([MS-OXRTFCP] §2.1.3.1.1).
    actual_crc = compute_crc(comp_data)
    if actual_crc != crc and sink is not None:
        sink.warn(WarnCode.RTF_CRC_FAIL,
                  f"RTF CRC 0x{actual_crc:08X} != stored 0x{crc:08X}",
                  where="rtf")

    out = _lzfu_inflate(comp_data, raw_size)
    return out


def _lzfu_inflate(comp: bytes, raw_size: int) -> bytes:
    """Run the LZFu control-byte loop against a fresh seeded dictionary.

    Implements [MS-OXRTFCP] §2.1.3.1.3 exactly: 4096-byte circular dictionary
    seeded with :data:`_INIT_DICT`, LSB-first control flags, 16-bit big-endian
    references (12-bit offset + 4-bit ``length+2``), self-referential offset
    terminates the stream.
    """
    dictionary = bytearray(_DICT_SIZE)
    dictionary[:len(_INIT_DICT)] = _INIT_DICT
    write_pos = len(_INIT_DICT) % _DICT_SIZE

    out = bytearray()
    i = 0
    n = len(comp)
    while i < n and len(out) < raw_size:
        control = comp[i]
        i += 1
        for bit in range(8):
            if i >= n or len(out) >= raw_size:
                break
            if (control >> bit) & 1:
                # Dictionary reference: 16-bit big-endian.
                if i + 1 >= n:
                    return bytes(out)
                token = (comp[i] << 8) | comp[i + 1]
                i += 2
                offset = (token >> 4) & 0x0FFF
                length = (token & 0x0F) + 2
                if offset == write_pos:
                    # End-of-stream marker.
                    return bytes(out)
                for _ in range(length):
                    src = dictionary[offset % _DICT_SIZE]
                    out.append(src)
                    dictionary[write_pos] = src
                    write_pos = (write_pos + 1) % _DICT_SIZE
                    offset = (offset + 1) % _DICT_SIZE
                    if len(out) >= raw_size:
                        break
            else:
                # Literal byte.
                lit = comp[i]
                i += 1
                out.append(lit)
                dictionary[write_pos] = lit
                write_pos = (write_pos + 1) % _DICT_SIZE
    return bytes(out)
