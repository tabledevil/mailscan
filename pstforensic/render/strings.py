"""Codepage-correct string decoding (PLAN §9.7, Appendix A H19).

  * ``PT_UNICODE  (0x001F)`` -> UTF-16LE (a stray leading BOM is stripped).
  * ``PT_STRING8  (0x001E)`` -> decoded using a codepage resolved by precedence:
        PidTagInternetCodepage (0x3FDE)
          -> PidTagMessageCodepage (0x3FFD)
          -> store-level codepage
          -> PidTagMessageLocaleId (LCID -> codepage)
          -> default 1252.

On decode failure: try ``charset_normalizer`` (optional dep) for detection, then
fall back to latin-1 (lossless for single bytes). The encoding actually used is
returned so callers can record it on ``MapiValue.encoding``.

Pure, no I/O.
"""
from __future__ import annotations

from typing import Optional

from ..proptypes import PropType, base_type

# Windows codepage number -> Python codec name. Covers the common multibyte and
# single-byte pages an analyst meets (PLAN §9.7).
_CP_MAP: dict[int, str] = {
    65001: "utf-8",
    1200: "utf-16-le",
    1201: "utf-16-be",
    1252: "cp1252",
    1250: "cp1250",
    1251: "cp1251",
    1253: "cp1253",
    1254: "cp1254",
    1255: "cp1255",
    1256: "cp1256",
    1257: "cp1257",
    1258: "cp1258",
    932: "shift_jis",
    936: "gbk",
    949: "euc_kr",
    950: "big5",
    874: "cp874",
    20127: "ascii",
    28591: "latin-1",
    28592: "iso8859-2",
    28595: "iso8859-5",
}

# A small LCID(low 16 bits) -> codepage mapping for the LCID precedence rung.
# Only common locales; unknown LCIDs fall through to the 1252 default.
_LCID_TO_CP: dict[int, int] = {
    0x0409: 1252,  # en-US
    0x0407: 1252,  # de-DE
    0x040C: 1252,  # fr-FR
    0x0411: 932,   # ja-JP
    0x0804: 936,   # zh-CN
    0x0404: 950,   # zh-TW
    0x0412: 949,   # ko-KR
    0x0419: 1251,  # ru-RU
}


def codepage_to_codec(cp: int) -> Optional[str]:
    """Map a Windows codepage number to a Python codec name, or ``None``."""
    return _CP_MAP.get(cp)


def lcid_to_codepage(lcid: int) -> int:
    """Map an LCID to its ANSI codepage (default 1252)."""
    return _LCID_TO_CP.get(lcid & 0xFFFF, 1252)


def resolve_codepage(
    *,
    internet_cpid: Optional[int] = None,
    message_cpid: Optional[int] = None,
    store_cpid: Optional[int] = None,
    locale_id: Optional[int] = None,
) -> int:
    """Resolve the effective PT_STRING8 codepage by precedence (Appendix A H19).

    PR_INTERNET_CPID -> PR_MESSAGE_CPID -> store -> LCID->cp -> 1252.
    """
    if internet_cpid:
        return internet_cpid
    if message_cpid:
        return message_cpid
    if store_cpid:
        return store_cpid
    if locale_id is not None:
        return lcid_to_codepage(locale_id)
    return 1252


class _Decoded:
    """Tiny record carrying the decoded text and the codec actually used."""

    __slots__ = ("text", "encoding")

    def __init__(self, text: str, encoding: str) -> None:
        self.text = text
        self.encoding = encoding


def decode_string(
    raw: bytes,
    prop_type: int,
    *,
    codepage: Optional[int] = None,
) -> str:
    """Decode a MAPI string property's raw bytes to ``str``.

    :param raw: the value bytes (no length prefix).
    :param prop_type: the MAPI property type (``0x001F`` unicode / ``0x001E``
        string8); the MV flag is tolerated and stripped.
    :param codepage: the resolved Windows codepage for ``PT_STRING8`` (see
        :func:`resolve_codepage`); ignored for unicode. Defaults to 1252.
    :returns: the decoded string (best-effort; never raises on bad bytes).
    """
    return decode_string_ex(raw, prop_type, codepage=codepage).text


def decode_string_ex(
    raw: bytes,
    prop_type: int,
    *,
    codepage: Optional[int] = None,
) -> _Decoded:
    """Like :func:`decode_string` but also reports the codec used.

    :returns: a record with ``.text`` and ``.encoding`` (the codec name).
    """
    if raw is None:
        return _Decoded("", "ascii")
    raw = bytes(raw)
    bt = base_type(prop_type)

    if bt == PropType.STRING:  # 0x001F PT_UNICODE
        # Strip a stray UTF-16LE BOM if present.
        if raw[:2] == b"\xff\xfe":
            raw = raw[2:]
        # Drop a trailing lone byte (odd length) defensively.
        if len(raw) % 2:
            raw = raw[:-1]
        return _Decoded(raw.decode("utf-16-le", "replace"), "utf-16-le")

    # PT_STRING8 (0x001E) and anything else: codepage path.
    cp = codepage if codepage else 1252
    codec = codepage_to_codec(cp) or "cp1252"
    try:
        return _Decoded(raw.decode(codec), codec)
    except (UnicodeDecodeError, LookupError):
        pass

    # charset_normalizer fallback (optional dependency).
    try:
        from charset_normalizer import from_bytes  # type: ignore

        best = from_bytes(raw).best()
        if best is not None:
            return _Decoded(str(best), best.encoding or "latin-1")
    except Exception:
        pass

    # Last resort: latin-1 is lossless for any byte sequence.
    return _Decoded(raw.decode("latin-1", "replace"), "latin-1")
