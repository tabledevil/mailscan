"""pstforensic logging — the debugging base for any host (MATT, pipelines).

The library logs under the ``pstforensic`` logger hierarchy and is silent by
default (NullHandler).  The host decides verbosity: MATT wires it into its own
``-v``/``-d`` handling; a pipeline can call :func:`enable_debug_log`.

Levels: INFO = phase milestones (open, walk, scan, inventory) with counts and
timings; DEBUG = every decision (variant evidence, crypt ladder, skipped
pages, every parser warning, every item's state/findings, every swallowed
failure with its code frames).  All records are content-free: structural ids,
offsets, sizes, codes — never property values, names or message text.
"""
from __future__ import annotations

import logging
import sys
from typing import Optional

log = logging.getLogger("pstforensic")
log.addHandler(logging.NullHandler())

FORMAT = "%(asctime)s %(levelname)-7s %(name)s %(module)s:%(lineno)d | %(message)s"


def enable_debug_log(path: Optional[str] = None, level: int = logging.DEBUG) -> logging.Handler:
    """Send pstforensic records to ``path`` (or stderr) at ``level``."""
    handler: logging.Handler = (logging.FileHandler(path, mode="a", encoding="utf-8")
                                if path else logging.StreamHandler(sys.stderr))
    handler.setLevel(level)
    handler.setFormatter(logging.Formatter(FORMAT))
    log.addHandler(handler)
    log.setLevel(min(level, log.level or level) if log.level else level)
    return handler
