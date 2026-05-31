"""pstforensic — a forensic-grade, host-static-safe PST/OST/MSG parser.

Recovery-first: reads corrupted stores, reconstructs deleted/orphaned items,
and exposes every MAPI property human-readably through one shared object model.

See docs/PST_OST_PARSER_PLAN.md for the design; Appendix A is authoritative for
all byte-level constants.
"""
from __future__ import annotations

__version__ = "0.0.1.dev0"

from .exceptions import (
    EncryptedStoreError,
    NotAMsgError,
    NotAPstError,
    ParseWarning,
    PstForensicError,
    UnsupportedStoreError,
    WarnCode,
    WarningSink,
)
from .mapi import (
    MapiAttachment,
    MapiMessage,
    MapiObject,
    MapiRecipient,
    MapiValue,
)
from .proptypes import PropType, make_tag, split_tag, tag_str

__all__ = [
    "__version__",
    # errors
    "PstForensicError",
    "NotAPstError",
    "NotAMsgError",
    "EncryptedStoreError",
    "UnsupportedStoreError",
    "ParseWarning",
    "WarnCode",
    "WarningSink",
    # model
    "MapiValue",
    "MapiObject",
    "MapiMessage",
    "MapiRecipient",
    "MapiAttachment",
    "PropType",
    "make_tag",
    "split_tag",
    "tag_str",
    # high-level entry points (filled in as layers land)
    "open_store",
    "open_msg",
    "RecoveryEngine",
]


def __getattr__(name):  # PEP 562 lazy attribute — keep imports cheap.
    """Lazily expose :class:`RecoveryEngine` without importing the cascade eagerly."""
    if name == "RecoveryEngine":
        from .recovery.engine import RecoveryEngine  # noqa: PLC0415

        return RecoveryEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def open_store(source, **kwargs):
    """Open a PST/OST store. Implemented at milestone M3 (messaging layer)."""
    from .messaging.store import open_store as _open  # noqa: PLC0415

    return _open(source, **kwargs)


def open_msg(source, **kwargs):
    """Open a native MSG message. Implemented at milestone M4."""
    from .msg.parser import open_msg as _open  # noqa: PLC0415

    return _open(source, **kwargs)
