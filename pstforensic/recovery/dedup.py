"""Dedup of re-carved duplicates (PLAN §8.6).

Hard-deleted items are frequently re-carved from several slack copies.  This
module collapses duplicates to a single highest-confidence instance and records
``duplicate_count`` on the survivor.

Dedup key (PLAN §8.6):
  * **normalized envelope** SHA-256 of ``from|to|subject|client_submit_time``
    when those render to non-empty values, else
  * **raw-PC-bytes** SHA-256 (the full carved PC payload) when the envelope is
    incomplete.

The highest-``confidence`` instance survives; on a tie the first seen wins.
"""
from __future__ import annotations

import hashlib
from typing import List, Optional, TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .engine import RecoveredItem

# Envelope PidTag ids used for the normalized dedup key ([MS-OXPROPS]).
_PID_SENDER_EMAIL = 0x0C1F   # PidTagSenderEmailAddress
_PID_SENDER_NAME = 0x0C1A    # PidTagSenderName
_PID_SUBJECT = 0x0037        # PidTagSubject
_PID_SUBMIT_TIME = 0x0039    # PidTagClientSubmitTime
_PID_DELIVERY_TIME = 0x0E06  # PidTagMessageDeliveryTime (fallback for time)
_PID_DISPLAY_TO = 0x0E04     # PidTagDisplayTo


def _render_str(item: "RecoveredItem", prop_id: int) -> str:
    """Render a string-ish property to text for keying, or ``""``."""
    msg = item.message
    if msg is None:
        return ""
    try:
        val = msg.render(prop_id)
    except Exception:
        return ""
    if isinstance(val, str):
        return val
    if val is None:
        return ""
    return str(val)


def envelope_key(item: "RecoveredItem") -> Optional[bytes]:
    """SHA-256 of the normalized envelope, or ``None`` if incomplete (§8.6).

    The envelope is ``from|to|subject|client_submit_time``.  When *every*
    component is empty the envelope is considered incomplete and the caller
    falls back to the raw-PC-bytes key.
    """
    sender = _render_str(item, _PID_SENDER_EMAIL) or _render_str(item, _PID_SENDER_NAME)
    to = _render_str(item, _PID_DISPLAY_TO)
    subject = _render_str(item, _PID_SUBJECT)
    time = _render_str(item, _PID_SUBMIT_TIME) or _render_str(item, _PID_DELIVERY_TIME)
    if not (sender or to or subject or time):
        return None
    norm = "\x1f".join((sender, to, subject, time)).encode("utf-8")
    return hashlib.sha256(b"ENV\x00" + norm).digest()


def raw_key(item: "RecoveredItem") -> bytes:
    """SHA-256 of the raw carved PC bytes (envelope-incomplete fallback, §8.6)."""
    raw = getattr(item.meta, "raw_pc", None) or b""
    if not raw:
        # No carved bytes recorded — fall back to (nid, subject) so distinct
        # nodes never collide spuriously.
        raw = f"{item.nid:#x}|{item.subject or ''}".encode("utf-8")
    return hashlib.sha256(b"RAW\x00" + (raw if isinstance(raw, bytes)
                                        else bytes(raw))).digest()


def dedup_key(item: "RecoveredItem") -> bytes:
    """Dedup key for ``item``: envelope hash if complete, else raw-PC hash (§8.6)."""
    return envelope_key(item) or raw_key(item)


def dedup(items: List["RecoveredItem"]) -> List["RecoveredItem"]:
    """Collapse duplicate carves, keeping the highest-confidence one (§8.6).

    The survivor's ``meta.duplicate_count`` is set to the number of instances
    that collapsed into it (1 if unique).  Input order of distinct keys is
    preserved so the result is deterministic.
    """
    survivors: dict[bytes, "RecoveredItem"] = {}
    counts: dict[bytes, int] = {}
    order: list[bytes] = []

    for item in items:
        key = dedup_key(item)
        counts[key] = counts.get(key, 0) + 1
        cur = survivors.get(key)
        if cur is None:
            survivors[key] = item
            order.append(key)
        elif item.meta.confidence > cur.meta.confidence:
            survivors[key] = item

    out: List["RecoveredItem"] = []
    for key in order:
        winner = survivors[key]
        winner.meta.duplicate_count = counts[key]
        out.append(winner)
    return out
