"""Per-analyzer persistent cache infrastructure.

Provides a lightweight key-value store backed by JSON files in ~/.matt/cache/.
Each analyzer gets its own namespace (file), preventing collisions.

Usage in an analyzer::

    from Utils.analyzer_cache import AnalyzerCache

    cache = AnalyzerCache("email")
    cache.set("relay:mx.google.com", {"provider": "Google", "seen": 42})
    info = cache.get("relay:mx.google.com")
    cache.increment("relay:mx.google.com", "seen")
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any

log = logging.getLogger("matt")


def _cache_dir() -> Path:
    """Return the cache root directory (~/.matt/cache/)."""
    return Path.home() / ".matt" / "cache"


class AnalyzerCache:
    """Simple JSON-backed key-value store for analyzer-local persistence.

    Each instance is scoped to a namespace (typically the analyzer name).
    Data is stored in ~/.matt/cache/{namespace}.json.

    The cache is lazy-loaded on first access and auto-saved on mutation.
    """

    def __init__(self, namespace: str):
        self.namespace = namespace
        self._path = _cache_dir() / f"{namespace}.json"
        self._data: dict[str, Any] | None = None
        self._dirty = False

    def _load(self):
        """Load cache from disk (lazy, called on first access)."""
        if self._data is not None:
            return
        if self._path.is_file():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
                return
            except (json.JSONDecodeError, OSError) as exc:
                log.debug("Cache load failed for %s: %s", self.namespace, exc)
        self._data = {}

    def _save(self):
        """Persist cache to disk."""
        if not self._dirty or self._data is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._data, indent=2, default=str), encoding="utf-8")
            tmp.replace(self._path)
            self._dirty = False
        except OSError as exc:
            log.debug("Cache save failed for %s: %s", self.namespace, exc)

    def get(self, key: str, default: Any = None) -> Any:
        """Retrieve a value by key."""
        self._load()
        return self._data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Store a value by key and persist."""
        self._load()
        self._data[key] = value
        self._dirty = True
        self._save()

    def delete(self, key: str) -> bool:
        """Remove a key. Returns True if it existed."""
        self._load()
        if key in self._data:
            del self._data[key]
            self._dirty = True
            self._save()
            return True
        return False

    def has(self, key: str) -> bool:
        """Check if a key exists."""
        self._load()
        return key in self._data

    def increment(self, key: str, field: str, amount: int = 1) -> int:
        """Increment a numeric field within a dict-typed value.

        If the key doesn't exist, creates it with {field: amount}.
        Returns the new value of the field.
        """
        self._load()
        entry = self._data.get(key, {})
        if not isinstance(entry, dict):
            entry = {}
        entry[field] = entry.get(field, 0) + amount
        self._data[key] = entry
        self._dirty = True
        self._save()
        return entry[field]

    def keys(self) -> list[str]:
        """Return all keys in this namespace."""
        self._load()
        return list(self._data.keys())

    def items(self) -> list[tuple[str, Any]]:
        """Return all key-value pairs."""
        self._load()
        return list(self._data.items())

    def clear(self) -> None:
        """Remove all entries."""
        self._data = {}
        self._dirty = True
        self._save()

    @property
    def size(self) -> int:
        """Number of entries in the cache."""
        self._load()
        return len(self._data)

    def touch(self, key: str) -> None:
        """Update the 'last_seen' timestamp of an entry (if it's a dict)."""
        self._load()
        entry = self._data.get(key)
        if isinstance(entry, dict):
            entry["last_seen"] = time.time()
            self._dirty = True
            self._save()
