"""Capability snapshot — what this installation can do, determined once.

Optional dependencies (MIME providers, analyzer libraries, system tools) are
checked once per process instead of on every object.  Objects then only carry
analyses that actually ran; what could not run is reported once, at the root,
with how many objects it affected (see ``Structure._build_capability_hints``).
"""
from __future__ import annotations

import logging
import shutil
import threading
from functools import lru_cache
from typing import Dict, List

log = logging.getLogger("matt")

SYSTEM_TOOLS = ("exiftool", "file", "unrar", "pdftoppm")

_lock = threading.Lock()
_warned: set = set()


@lru_cache(maxsize=1)
def provider_status() -> Dict[str, Dict[str, str]]:
    """MIME provider availability, by provider name (checked once)."""
    from Utils.filetype import get_provider_status
    try:
        return {s["provider"]: s for s in get_provider_status()}
    except Exception as exc:   # never let a probe break analysis
        log.debug("provider status probe failed: %s", exc)
        return {}


def provider_available(name: str) -> bool:
    st = provider_status().get(name)
    return True if st is None else bool(st.get("available"))


@lru_cache(maxsize=None)
def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@lru_cache(maxsize=None)
def analyzer_status(cls) -> tuple:
    """``(available, reason)`` for an Analyzer subclass (checked once)."""
    try:
        return tuple(cls.is_available())
    except Exception as exc:
        return False, f"availability check failed: {exc}"


def missing_providers() -> List[Dict[str, str]]:
    return [s for s in provider_status().values() if not s.get("available")]


def warn_once(key: str, message: str) -> None:
    """Log a missing-dependency warning once per process, not per object."""
    with _lock:
        if key in _warned:
            return
        _warned.add(key)
    log.warning(message)


def reset() -> None:
    """Forget cached probes (tests, or after installing something)."""
    provider_status.cache_clear()
    tool_available.cache_clear()
    analyzer_status.cache_clear()
    with _lock:
        _warned.clear()
