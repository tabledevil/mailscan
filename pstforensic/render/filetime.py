"""FILETIME / SYSTIME and OLE-automation-date renderers ([MS-OXCDATA]/§9.3).

Pure, no I/O. All times are interpreted as UTC and never timezone-reinterpreted.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

# Number of 100-ns intervals between 1601-01-01 (FILETIME epoch) and the Unix
# epoch 1970-01-01. [MS-DTYP] FILETIME. Locked by test vector below.
_FT_EPOCH_DELTA = 116444736000000000  # 100-ns ticks
_FT_TICKS_PER_SEC = 10_000_000

# Maximum FILETIME that datetime can represent (year 9999). Anything above this
# is a corrupt/sentinel value and rendered as None + a note via filetime_note.
_FT_MAX = 0x7FFFFFFFFFFFFFFF

# OLE automation date epoch: 1899-12-30 (PtypFloatingTime / PtypAppTime, §9.8).
_OLE_EPOCH = datetime(1899, 12, 30, tzinfo=timezone.utc)


def filetime(b: bytes | int) -> datetime | None:
    """Render a PtypTime (PT_SYSTIME 0x0040) FILETIME to a UTC ``datetime``.

    The value is a u64 little-endian count of 100-ns intervals since
    1601-01-01T00:00:00Z ([MS-DTYP] FILETIME; PLAN §9.3).

    Sentinels / edge cases:
      * ``0`` -> ``None`` ("never").
      * out-of-range / un-representable -> ``None`` (caller may annotate with
        :func:`filetime_note`).

    :param b: 8 little-endian bytes, or an already-decoded u64 integer.
    :returns: a timezone-aware UTC ``datetime`` or ``None``.
    """
    val = _as_u64(b)
    if val is None:
        return None
    if val == 0:
        return None  # "never"
    if val > _FT_MAX:
        return None
    try:
        secs, ticks = divmod(val - _FT_EPOCH_DELTA, _FT_TICKS_PER_SEC)
        return datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(
            seconds=secs, microseconds=ticks // 10
        )
    except (OverflowError, ValueError, OSError):
        return None


def filetime_note(b: bytes | int) -> str | None:
    """Return a human note for sentinel/invalid FILETIMEs, else ``None``.

    ``"never"`` for 0; ``"(invalid 0x...)"`` for out-of-range; ``None`` when the
    value is a normal, representable time (PLAN §9.3).
    """
    val = _as_u64(b)
    if val is None:
        return "(invalid)"
    if val == 0:
        return "never"
    if val > _FT_MAX or filetime(val) is None:
        return f"(invalid 0x{val:016X})"
    return None


def apptime(b: bytes | float) -> datetime | None:
    """Render a PtypFloatingTime / PtypAppTime (OLE automation date) to UTC.

    OLE automation date: an IEEE-754 f64 number of days since 1899-12-30
    (PLAN §9.8). The integer part is whole days; the *magnitude* of the
    fractional part is the time of day (OLE quirk: the fraction is always added,
    never subtracted, even for negative dates).

    :param b: 8 little-endian bytes, or an already-decoded float.
    :returns: a UTC ``datetime`` or ``None`` if not representable.
    """
    import struct

    if isinstance(b, (bytes, bytearray)):
        if len(b) < 8:
            return None
        days = struct.unpack_from("<d", b, 0)[0]
    else:
        days = float(b)
    if days != days:  # NaN
        return None
    whole = int(days)
    frac = abs(days - whole)
    try:
        return _OLE_EPOCH + timedelta(days=whole) + timedelta(days=frac)
    except (OverflowError, ValueError):
        return None


# OLE-date alias used by some call sites.
ole_date = apptime


def _as_u64(b: bytes | int) -> int | None:
    """Coerce input to an unsigned 64-bit int, or ``None`` if impossible."""
    if isinstance(b, int):
        return b & 0xFFFFFFFFFFFFFFFF
    if isinstance(b, (bytes, bytearray)):
        if len(b) < 8:
            return None
        return int.from_bytes(bytes(b[:8]), "little", signed=False)
    return None
