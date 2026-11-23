"""Persistent structural index cache — repeated opens skip the expensive work.

What is cached, per store and per pstforensic version:

  * ``btree``  — the live NBT/BBT walk (entries, page verdicts, skipped pages)
  * ``scan``   — the full-file :class:`~pstforensic.ndb.scan.ScanIndex`
  * ``items``  — the inventory index: one record per item (state, provenance,
    NID/BID, parent NID) and the carving result

Everything in it is **structural**: offsets, NIDs, BIDs, sizes, verdict flags,
state names.  No property values, folder names, subjects or file names — the
cache file is named after a fingerprint of the store's bytes, never after its
path.

The cache is opt-in for the library (``open_store(path, cache_dir=...)`` or
``PSTFORENSIC_CACHE_DIR``); a forensic library does not write anywhere unasked.
The CLI tools and MATT turn it on.

Key: by content, never by name — many same-named stores in a leak never
collide, and byte-identical duplicates share one entry.  Either the caller's
own content hash (``cache_key=``, e.g. the SHA-256 a pipeline already has) or a
sampled fingerprint: size + first 64 KiB (header/ROOT) + last 1 MiB + 64 windows
of 4 KiB spread over the file.  Loading additionally checks that the stored
header bytes equal the file's.

Disk: entries are zlib-compressed; the directory is capped (default 4 GiB,
``PSTFORENSIC_CACHE_MAX_MB``) with least-recently-used eviction, and nothing is
written while the volume has less than 2 GiB free.

Concurrency: writes go to a temp file and are renamed into place (readers
never see partial entries; concurrent writers of the same key write identical
data); eviction runs under a non-blocking lock file and tolerates entries that
vanish underneath it.  Several processes can share one cache directory.

Entries are read with a restricted unpickler that only rebuilds pstforensic's
own record classes and builtins.
"""
from __future__ import annotations

import hashlib
import io
import logging
import os
import pickle
import shutil
import tempfile
import time
import zlib
from typing import Any, Optional

_log = logging.getLogger("pstforensic.cache")
FORMAT = 3
_TAIL = 1 << 20
_HEAD = 64 << 10
_WINDOWS, _WIN = 64, 4096
MIN_FREE = 2 << 30
_ALLOWED = {
    ("builtins", "set"), ("builtins", "frozenset"), ("builtins", "dict"),
    ("builtins", "list"), ("builtins", "tuple"), ("builtins", "bytes"),
    ("builtins", "int"), ("builtins", "str"), ("builtins", "bool"),
    ("builtins", "float"), ("builtins", "object"), ("collections", "OrderedDict"),
    ("copyreg", "_reconstructor"), ("copyreg", "__newobj__"),
}
_ALLOWED_MODULES = ("pstforensic.ndb.", "pstforensic.integrity", "pstforensic.exceptions",
                    "pstforensic.cache")


class _SafeUnpickler(pickle.Unpickler):
    def find_class(self, module: str, name: str):
        if (module, name) in _ALLOWED or module.startswith(_ALLOWED_MODULES):
            return super().find_class(module, name)
        raise pickle.UnpicklingError(f"cache: refusing {module}.{name}")


def resolve_dir(cache_dir: Optional[str]) -> Optional[str]:
    """``cache_dir`` if given, else ``$PSTFORENSIC_CACHE_DIR``, else None (off)."""
    d = cache_dir or os.environ.get("PSTFORENSIC_CACHE_DIR")
    return os.path.expanduser(d) if d else None


def default_dir() -> str:
    """Per-user default for tools: ``$XDG_CACHE_HOME/pstforensic``."""
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "pstforensic")


def max_bytes() -> int:
    try:
        return int(os.environ.get("PSTFORENSIC_CACHE_MAX_MB", "4096")) << 20
    except ValueError:
        return 4096 << 20


def fingerprint(reader) -> str:
    """Content fingerprint (see module doc) — independent of name and mtime."""
    from . import __version__
    mv, size = reader._data, reader.size
    h = hashlib.sha256(f"{FORMAT}|{__version__}|{size}|".encode())
    h.update(bytes(mv[:min(size, _HEAD)]))
    h.update(bytes(mv[max(0, size - _TAIL):size]))
    if size > _WIN:
        for i in range(_WINDOWS):
            o = (size - _WIN) * i // max(1, _WINDOWS - 1)
            h.update(bytes(mv[o:o + _WIN]))
    return h.hexdigest()[:48]


class IndexCache:
    """One store's cache entries under ``<dir>/<fingerprint>/<part>.pkl``."""

    def __init__(self, directory: str, key: str, header: bytes = b""):
        self.root = directory
        self.dir = os.path.join(directory, key)
        self.key = key
        self.header = header

    @classmethod
    def for_reader(cls, reader, cache_dir: Optional[str],
                   cache_key: Optional[str] = None) -> Optional["IndexCache"]:
        d = resolve_dir(cache_dir)
        if not d:
            return None
        try:
            from . import __version__
            if cache_key:   # caller's content hash: still bind to format/version
                key = hashlib.sha256(f"{FORMAT}|{__version__}|{cache_key}".encode()
                                     ).hexdigest()[:48]
            else:
                key = fingerprint(reader)
            return cls(d, key, bytes(reader._data[:min(reader.size, 4096)]))
        except Exception as exc:   # never let caching break a read
            _log.warning("cache: disabled (%s)", type(exc).__name__)
            return None

    def load(self, part: str, params: Any = None) -> Optional[Any]:
        path = os.path.join(self.dir, f"{part}.pkl")
        try:
            with open(path, "rb") as fh:
                raw = zlib.decompress(fh.read())
            rec = _SafeUnpickler(io.BytesIO(raw)).load()
            os.utime(self.dir)            # LRU: mark the entry as used
        except FileNotFoundError:
            return None
        except Exception as exc:
            _log.warning("cache: %s unreadable (%s), rebuilding", part, type(exc).__name__)
            return None
        if not isinstance(rec, dict) or rec.get("params") != params:
            return None
        if rec.get("header") != self.header:
            _log.warning("cache: %s key matched but header differs — ignored", part)
            return None
        _log.info("cache: %s loaded", part)
        return rec.get("data")

    def save(self, part: str, data: Any, params: Any = None) -> None:
        try:
            os.makedirs(self.root, exist_ok=True)
            if shutil.disk_usage(self.root).free < MIN_FREE:
                _log.warning("cache: %s not saved (less than %d MiB free)", part,
                             MIN_FREE >> 20)
                return
            blob = zlib.compress(pickle.dumps(
                {"params": params, "header": self.header, "data": data},
                protocol=pickle.HIGHEST_PROTOCOL), 1)
            if len(blob) > max_bytes() // 2:
                _log.warning("cache: %s not saved (entry larger than half the cap)", part)
                return
            os.makedirs(self.dir, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=self.dir, suffix=".tmp")
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, os.path.join(self.dir, f"{part}.pkl"))
            _log.info("cache: %s saved (%d KiB)", part, len(blob) >> 10)
            evict(self.root, keep=self.key)
        except Exception as exc:
            _log.warning("cache: %s not saved (%s)", part, type(exc).__name__)


def _du(path: str) -> int:
    total = 0
    for r, _, fs in os.walk(path):
        for f in fs:
            try:
                total += os.path.getsize(os.path.join(r, f))
            except OSError:
                pass
    return total


def evict(root: str, keep: Optional[str] = None, limit: Optional[int] = None) -> int:
    """Drop least-recently-used entries until the directory fits ``limit``.
    Non-blocking: if another process is evicting, return immediately."""
    limit = max_bytes() if limit is None else limit
    lock = os.path.join(root, ".evict.lock")
    try:
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        try:   # a crashed evictor's lock goes stale after 10 minutes
            if time.time() - os.path.getmtime(lock) > 600:
                os.unlink(lock)
        except OSError:
            pass
        return 0
    removed = 0
    try:
        os.close(fd)
        entries = []
        for name in os.listdir(root):
            p = os.path.join(root, name)
            if os.path.isdir(p):
                try:
                    entries.append((os.path.getmtime(p), name, _du(p)))
                except OSError:
                    pass
        total = sum(e[2] for e in entries)
        for _mtime, name, size in sorted(entries):
            if total <= limit:
                break
            if name == keep:
                continue
            shutil.rmtree(os.path.join(root, name), ignore_errors=True)
            total -= size
            removed += 1
        # stale temp files of crashed writers
        for r, _, fs in os.walk(root):
            for f in fs:
                fp = os.path.join(r, f)
                if f.endswith(".tmp") and time.time() - os.path.getmtime(fp) > 3600:
                    try:
                        os.unlink(fp)
                    except OSError:
                        pass
    finally:
        try:
            os.unlink(lock)
        except OSError:
            pass
    if removed:
        _log.info("cache: evicted %d entries", removed)
    return removed
