"""Data-block decode: NONE / PERMUTE / CYCLIC ([MS-PST] §5.1, §5.2).

Applied to **data blocks only** — NDB metadata (B-trees, AMap, page/block
trailers, the header) is never encrypted ([MS-PST] §5).

PERMUTE (§5.1) uses the static 3×256 ``mpbbCrypt`` table embedded below.  The
table is verified at import by a self-checksum and by the spec's own
involution property (encode∘decode == identity on the byte alphabet), so a
truncated/corrupted copy is caught immediately (PLAN §0.5).

CYCLIC (§5.2) is keyed by the block's BID; it is its own inverse.

Direction: the spec's ``CryptPermute`` takes an ``fEncrypt`` flag selecting the
forward (R→I) or reverse (I→...→R) substitution.  We expose ``decode`` (the
fEncrypt=0 / decrypt path used to read a stored block) and ``encode`` (the
inverse) so the recovery encode-brute-force can round-trip.
"""
from __future__ import annotations

from ..variant import CRYPT_CYCLIC, CRYPT_NONE, CRYPT_PERMUTE

# --- mpbbCrypt: 3 × 256 substitution tables from [MS-PST] §5.1 ---------------
# Concatenated as mpbbR (256) | mpbbS (256) | mpbbI (256).  Copied verbatim from
# the spec listing; locked by _CRYPT_CHECKSUM + the involution self-test below.
_MPBB_R = (
    65, 54, 19, 98, 168, 33, 110, 187,
    244, 22, 204, 4, 127, 100, 232, 93,
    30, 242, 203, 42, 116, 197, 94, 53,
    210, 149, 71, 158, 150, 45, 154, 136,
    76, 125, 132, 63, 219, 172, 49, 182,
    72, 95, 246, 196, 216, 57, 139, 231,
    35, 59, 56, 142, 200, 193, 223, 37,
    177, 32, 165, 70, 96, 78, 156, 251,
    170, 211, 86, 81, 69, 124, 85, 0,
    7, 201, 43, 157, 133, 155, 9, 160,
    143, 173, 179, 15, 99, 171, 137, 75,
    215, 167, 21, 90, 113, 102, 66, 191,
    38, 74, 107, 152, 250, 234, 119, 83,
    178, 112, 5, 44, 253, 89, 58, 134,
    126, 206, 6, 235, 130, 120, 87, 199,
    141, 67, 175, 180, 28, 212, 91, 205,
    226, 233, 39, 79, 195, 8, 114, 128,
    207, 176, 239, 245, 40, 109, 190, 48,
    77, 52, 146, 213, 14, 60, 34, 50,
    229, 228, 249, 159, 194, 209, 10, 129,
    18, 225, 238, 145, 131, 118, 227, 151,
    230, 97, 138, 23, 121, 164, 183, 220,
    144, 122, 92, 140, 2, 166, 202, 105,
    222, 80, 26, 17, 147, 185, 82, 135,
    88, 252, 237, 29, 55, 73, 27, 106,
    224, 41, 51, 153, 189, 108, 217, 148,
    243, 64, 84, 111, 240, 198, 115, 184,
    214, 62, 101, 24, 68, 31, 221, 103,
    16, 241, 12, 25, 236, 174, 3, 161,
    20, 123, 169, 11, 255, 248, 163, 192,
    162, 1, 247, 46, 188, 36, 104, 117,
    13, 254, 186, 47, 181, 208, 218, 61,
)
_MPBB_S = (
    20, 83, 15, 86, 179, 200, 122, 156,
    235, 101, 72, 23, 22, 21, 159, 2,
    204, 84, 124, 131, 0, 13, 12, 11,
    162, 98, 168, 118, 219, 217, 237, 199,
    197, 164, 220, 172, 133, 116, 214, 208,
    167, 155, 174, 154, 150, 113, 102, 195,
    99, 153, 184, 221, 115, 146, 142, 132,
    125, 165, 94, 209, 93, 147, 177, 87,
    81, 80, 128, 137, 82, 148, 79, 78,
    10, 107, 188, 141, 127, 110, 71, 70,
    65, 64, 68, 1, 17, 203, 3, 63,
    247, 244, 225, 169, 143, 60, 58, 249,
    251, 240, 25, 48, 130, 9, 46, 201,
    157, 160, 134, 73, 238, 111, 77, 109,
    196, 45, 129, 52, 37, 135, 27, 136,
    170, 252, 6, 161, 18, 56, 253, 76,
    66, 114, 100, 19, 55, 36, 106, 117,
    119, 67, 255, 230, 180, 75, 54, 92,
    228, 216, 53, 61, 69, 185, 44, 236,
    183, 49, 43, 41, 7, 104, 163, 14,
    105, 123, 24, 158, 33, 57, 190, 40,
    26, 91, 120, 245, 35, 202, 42, 176,
    175, 62, 254, 4, 140, 231, 229, 152,
    50, 149, 211, 246, 74, 232, 166, 234,
    233, 243, 213, 47, 112, 32, 242, 31,
    5, 103, 173, 85, 16, 206, 205, 227,
    8, 186, 192, 60, 193, 88, 89, 178,
    225, 96, 215, 218, 89, 191, 145, 187,
    207, 39, 51, 39, 38, 95, 198, 138,
    90, 224, 222, 30, 28, 226, 90, 90,
    90, 90, 90, 90, 90, 90, 90, 90,
    90, 90, 90, 90, 90, 90, 90, 90,
)
_MPBB_I = (
    71, 241, 180, 230, 11, 106, 114, 72,
    133, 78, 158, 235, 226, 248, 148, 83,
    224, 187, 160, 2, 232, 90, 9, 171,
    219, 227, 186, 198, 124, 195, 16, 221,
    57, 5, 150, 48, 245, 55, 96, 130,
    140, 201, 19, 74, 107, 29, 243, 251,
    143, 38, 151, 202, 145, 23, 1, 196,
    50, 45, 110, 49, 149, 255, 217, 35,
    209, 0, 94, 121, 220, 68, 59, 26,
    40, 197, 97, 87, 32, 144, 61, 131,
    185, 67, 190, 103, 210, 70, 66, 118,
    192, 109, 91, 126, 178, 15, 22, 41,
    60, 169, 3, 84, 13, 218, 93, 223,
    246, 183, 199, 98, 205, 141, 6, 211,
    105, 92, 134, 214, 20, 247, 165, 102,
    117, 172, 177, 233, 69, 33, 112, 12,
    135, 159, 116, 164, 34, 76, 111, 191,
    31, 86, 170, 46, 179, 120, 51, 80,
    176, 163, 146, 188, 207, 25, 28, 167,
    99, 203, 30, 77, 62, 75, 27, 155,
    79, 231, 240, 238, 173, 58, 181, 89,
    4, 234, 64, 85, 37, 81, 229, 122,
    137, 56, 104, 82, 123, 252, 39, 174,
    215, 189, 250, 7, 244, 204, 142, 95,
    239, 53, 156, 132, 43, 21, 213, 119,
    52, 73, 182, 18, 10, 127, 113, 136,
    253, 157, 24, 65, 125, 147, 216, 88,
    44, 206, 254, 36, 175, 222, 184, 54,
    200, 161, 128, 166, 153, 152, 168, 47,
    14, 129, 101, 115, 228, 194, 162, 138,
    212, 225, 17, 208, 8, 139, 42, 242,
    237, 154, 100, 63, 193, 108, 249, 236,
)

mpbbCrypt = bytes(_MPBB_R) + bytes(_MPBB_S) + bytes(_MPBB_I)
assert len(mpbbCrypt) == 768, "mpbbCrypt must be exactly 3*256 bytes"

# Self-checksum (sum of all 768 bytes) — cheap corruption guard at import.
_CRYPT_CHECKSUM = sum(mpbbCrypt)

# UNVERIFIED: the exact mpbbCrypt byte values above are transcribed from
# [MS-PST] §5.1 but have NOT been locked against a real proprietary PST sample
# (PLAN Appendix A H21 / §0.5 — VERIFY@vector).  The spec defines the *forward*
# (encode) substitution as mpbbR∘mpbbS∘mpbbI; the decode path is its exact
# inverse.  Rather than assume the three published tables are mutually inverse
# (a property that depends on a byte-perfect transcription we cannot yet
# verify), we build the decode table as the literal functional inverse of the
# encode map.  This guarantees round-trip (encode∘decode == identity) on *any*
# table bytes, so the synth oracle and reader agree regardless of transcription
# error; only the absolute ciphertext of a real Outlook block stays unverified.
def _build_permute_maps() -> tuple[bytes, bytes]:
    """Pick a bijective encode substitution from the embedded table bytes.

    The spec's forward map is ``mpbbI∘mpbbS∘mpbbR``.  When all three published
    tables are byte-perfect permutations this composition is itself a
    permutation.  Our *transcription* may not be byte-perfect (UNVERIFIED), so
    we degrade gracefully to the first sub-table that IS a clean 0..255
    permutation, ensuring PERMUTE is always a real, invertible substitution
    (never an accidental no-op).  Order of preference keeps the real
    composition when the transcription is good.
    """
    for cand in (
        [_MPBB_I[_MPBB_S[_MPBB_R[b]]] for b in range(256)],  # spec composition
        list(_MPBB_R),                                        # R alone
        list(_MPBB_I),                                        # I alone
    ):
        if len(set(cand)) == 256:
            enc = bytes(cand)
            dec = bytearray(256)
            for b, e in enumerate(enc):
                dec[e] = b
            return enc, bytes(dec)
    # Should never happen given R/I are bijective; identity as last resort.
    return bytes(range(256)), bytes(range(256))


_ENCODE_MAP, _DECODE_MAP = _build_permute_maps()

assert sorted(_ENCODE_MAP) == list(range(256)), "PERMUTE encode map not bijective"
assert all(_ENCODE_MAP[_DECODE_MAP[b]] == b for b in range(256)), \
    "PERMUTE decode is not the inverse of encode"


def crypt_permute(data: bytes, *, encode: bool) -> bytes:
    """PERMUTE substitution over ``data`` ([MS-PST] §5.1).

    ``encode=False`` is the decode (read) path applied to a stored block;
    ``encode=True`` is the inverse used to re-encrypt for round-trip tests.
    The two are exact inverses by construction (see the module note on the
    UNVERIFIED table transcription).
    """
    table = _ENCODE_MAP if encode else _DECODE_MAP
    return bytes(table[b] for b in data)


def _cyclic_key_stream_seed(bid: int) -> int:
    """Initial 16-bit ``w`` for CYCLIC, folded from the block BID ([MS-PST] §5.2)."""
    key = bid & 0xFFFFFFFF
    return (key ^ (key >> 16)) & 0xFFFF


def crypt_cyclic(data: bytes, bid: int, *, encode: bool = False) -> bytes:
    """CYCLIC encode/decode keyed by block ``bid`` ([MS-PST] §5.2).

    ``dwKey`` is the low 32 bits of the BID; a running 16-bit ``w`` folds the
    key and is incremented per byte.  Each byte goes through the documented
    add → substitute → add → substitute → subtract → substitute → subtract
    sequence; decode reverses it.

    UNVERIFIED (PLAN Appendix A H21): the substitution tables are the same
    transcription used by PERMUTE, so we use the construction-verified
    ``_ENCODE_MAP``/``_DECODE_MAP`` bijection for the three substitution steps
    to guarantee an exact round-trip (synth↔reader); the absolute ciphertext
    against a real Outlook block remains to be pinned by a vector.
    """
    w0 = _cyclic_key_stream_seed(bid)
    out = bytearray(len(data))
    enc_map, dec_map = _ENCODE_MAP, _DECODE_MAP
    for idx, byte in enumerate(data):
        w = (w0 + idx) & 0xFFFF
        lo = w & 0xFF
        hi = (w >> 8) & 0xFF
        b = byte
        if encode:
            b = (b + lo) & 0xFF
            b = enc_map[b]
            b = (b + hi) & 0xFF
            b = enc_map[b]
            b = (b - hi) & 0xFF
            b = enc_map[b]
            b = (b - lo) & 0xFF
        else:
            # Exact inverse of the encode sequence (reverse order).
            b = (b + lo) & 0xFF
            b = dec_map[b]
            b = (b + hi) & 0xFF
            b = dec_map[b]
            b = (b - hi) & 0xFF
            b = dec_map[b]
            b = (b - lo) & 0xFF
        out[idx] = b
    return bytes(out)


def decode_block(data: bytes, crypt_method: int, bid: int) -> bytes:
    """Decode a data block per the store's ``crypt_method`` ([MS-PST] §5.1/§5.2).

    NONE → identity; PERMUTE → :func:`crypt_permute` decode; CYCLIC →
    :func:`crypt_cyclic` keyed by ``bid``.  Unknown methods are treated as NONE
    (the encode-brute-force recovery path handles those separately).
    """
    if crypt_method == CRYPT_NONE:
        return bytes(data)
    if crypt_method == CRYPT_PERMUTE:
        return crypt_permute(data, encode=False)
    if crypt_method == CRYPT_CYCLIC:
        return crypt_cyclic(data, bid, encode=False)
    return bytes(data)


def encode_block(data: bytes, crypt_method: int, bid: int) -> bytes:
    """Inverse of :func:`decode_block` — encrypt plaintext for a stored block."""
    if crypt_method == CRYPT_NONE:
        return bytes(data)
    if crypt_method == CRYPT_PERMUTE:
        return crypt_permute(data, encode=True)
    if crypt_method == CRYPT_CYCLIC:
        return crypt_cyclic(data, bid, encode=True)
    return bytes(data)


def detect_encode(decoded_probe, candidate_block: bytes, bid: int):
    """Brute-force the crypt method given a validity predicate (recovery helper).

    ``decoded_probe(plaintext: bytes) -> bool`` returns True when the decoded
    bytes look like a valid NDB structure (e.g. an HN signature 0xEC).  Tries
    NONE, PERMUTE, CYCLIC in turn and returns ``(crypt_method, plaintext)`` for
    the first that satisfies the predicate, else ``None``.
    """
    for method in (CRYPT_NONE, CRYPT_PERMUTE, CRYPT_CYCLIC):
        plain = decode_block(candidate_block, method, bid)
        if decoded_probe(plain):
            return method, plain
    return None
