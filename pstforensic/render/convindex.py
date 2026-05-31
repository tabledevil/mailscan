"""Conversation-index rendering ([MS-OXOMSG] §2.2.1.3; PLAN §9.6, Appendix A H16).

``PR_CONVERSATION_INDEX (0x0071, PtypBinary)`` encodes a message's place in a
conversation thread. Layout:

    Reserved   1 byte   (0x01)
    HeaderTime 5 bytes  high-order bits of a FILETIME (see below)
    GUID       16 bytes the conversation's GUID
    Children   N x 5 bytes

The 5-byte header time is **not** "100ms units" (Appendix A H16). It is the
high 40 bits of a 64-bit FILETIME: bytes [1..6] of the index are FILETIME bits
[63..24] (big-endian within the field), i.e. ``FILETIME = header40 << 24`` with
the low 24 bits masked to zero.

Each 5-byte child block decodes (big-endian, [MS-OXOMSG] §2.2.1.3) to:
  * bit 63       (TimeDelta high bit) selects the scale of the delta;
  * next 31 bits the FILETIME delta:
        high bit 0 => delta = value << 18  (≈ value * 1.0 s)
        high bit 1 => delta = value << 10  (≈ value / 256 s, finer resolution)
  * next 4 bits  a random component (ignored for time);
  * final 1 bit  a sequence-count component (ignored for time).
The running FILETIME accumulates the deltas down the chain, giving each reply an
absolute UTC time.

Pure, no I/O.
"""
from __future__ import annotations

from typing import Any

from .filetime import filetime
from .guid import guid

# A FILETIME delta unit is 100 ns. 1.0 s = 1e7 ticks ≈ 2**23.25; the spec uses
# fixed shifts of 18 (coarse) and 10 (fine) on the 31-bit field ([MS-OXOMSG]
# §2.2.1.3). UNVERIFIED exact shift constants — locked direction, see test.
_DELTA_SHIFT_COARSE = 18  # UNVERIFIED
_DELTA_SHIFT_FINE = 10    # UNVERIFIED


def conversation_index(b: bytes, sink: Any = None) -> dict[str, Any]:
    """Parse a conversation index into a thread tree with absolute UTC times.

    :param b: raw ``PR_CONVERSATION_INDEX`` bytes.
    :param sink: optional :class:`~pstforensic.exceptions.WarningSink` to record
        ``UNVERIFIED_CONST`` for the child-delta scale constants.
    :returns: a dict with ``guid``, ``header_time`` (ISO-8601 / ``None``),
        ``header_filetime`` (raw u64), ``children`` (list of
        ``{filetime, time, raw_hex}``) and ``corrupt`` (bool) when the length is
        not ``22 + 5*N``.
    """
    out: dict[str, Any] = {"corrupt": False, "children": []}
    if not isinstance(b, (bytes, bytearray)) or len(b) < 22:
        out["corrupt"] = True
        out["guid"] = None
        out["header_time"] = None
        out["header_filetime"] = None
        return out
    b = bytes(b)

    out["reserved"] = b[0]
    # 5-byte header time = high 40 bits of a FILETIME, big-endian in the field.
    header40 = int.from_bytes(b[1:6], "big")
    header_ft = header40 << 24
    out["header_filetime"] = header_ft
    dt = filetime(header_ft)
    out["header_time"] = dt.isoformat() if dt else None

    out["guid"] = guid(b[6:22])

    tail = b[22:]
    if len(tail) % 5 != 0:
        out["corrupt"] = True
    if sink is not None and tail:
        from ..exceptions import WarnCode
        sink.warn(WarnCode.UNVERIFIED_CONST,
                  "conversation-index child delta scale shifts (18/10) unverified",
                  where="conv_index")

    running_ft = header_ft
    n_children = len(tail) // 5
    for idx in range(n_children):
        block = tail[idx * 5:idx * 5 + 5]
        delta_ft = _decode_child_delta(int.from_bytes(block, "big"))
        running_ft += delta_ft
        cdt = filetime(running_ft)
        out["children"].append(
            {
                "filetime": running_ft,
                "time": cdt.isoformat() if cdt else None,
                "raw_hex": block.hex(),
            }
        )
    return out


def _decode_child_delta(value40: int) -> int:
    """Decode one 5-byte (40-bit) child block to a FILETIME delta (100-ns ticks).

    [MS-OXOMSG] §2.2.1.3: top bit selects the scale of the 31-bit delta field.
    """
    high_bit = (value40 >> 39) & 1
    delta31 = (value40 >> 8) & 0x7FFFFFFF  # next 31 bits
    if high_bit:
        return delta31 << _DELTA_SHIFT_FINE
    return delta31 << _DELTA_SHIFT_COARSE
