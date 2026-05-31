"""Bounds-guarded, lazy file access for multi-GB stores.

The whole point of a forensic reader is that it must never crash on a hostile
or truncated file: every read is clamped to the physical size and a short read
is reported (not an exception) so the recovery engine can carve the survivor
prefix (PLAN AC-2/AC-8).
"""
from __future__ import annotations

import mmap
import os
import struct
from typing import BinaryIO

from .exceptions import WarnCode, WarningSink


class FileReader:
    """A read-only window over bytes, mmap, or an open file.

    Use :meth:`read` for bounds-guarded slices and the ``u8/u16/u32/u64``
    helpers for little-endian integers (the PST byte order throughout).
    """

    def __init__(self, source, sink: WarningSink | None = None, *, name: str = "<bytes>"):
        self.sink = sink or WarningSink()
        self.name = name
        self._mmap = None
        self._owns = False
        if isinstance(source, (bytes, bytearray, memoryview)):
            self._data = memoryview(bytes(source))
            self._size = len(self._data)
        elif isinstance(source, (str, os.PathLike)):
            self.name = os.fspath(source)
            fh = open(source, "rb")
            self._owns = True
            self._fh: BinaryIO = fh
            self._size = os.fstat(fh.fileno()).st_size
            self._mmap = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) if self._size else None
            self._data = memoryview(self._mmap) if self._mmap is not None else memoryview(b"")
        elif hasattr(source, "read"):
            blob = source.read()
            self._data = memoryview(bytes(blob))
            self._size = len(self._data)
        else:  # pragma: no cover - defensive
            raise TypeError(f"unsupported source: {type(source)!r}")

    # -- lifecycle ---------------------------------------------------------
    @property
    def size(self) -> int:
        return self._size

    def close(self) -> None:
        if self._mmap is not None:
            self._mmap.close()
            self._mmap = None
        if self._owns and getattr(self, "_fh", None) is not None:
            self._fh.close()

    def __enter__(self) -> "FileReader":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- core read ---------------------------------------------------------
    def read(self, offset: int, length: int, *, where: str = "") -> bytes:
        """Return up to ``length`` bytes at ``offset``, clamped to EOF.

        A short or out-of-range read records ``OUT_OF_BOUNDS`` and returns the
        available bytes (possibly empty) rather than raising.
        """
        if offset < 0:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS, f"negative offset {offset}", where)
            return b""
        if offset >= self._size:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"offset {offset} >= size {self._size}", where)
            return b""
        end = min(offset + length, self._size)
        if end - offset < length:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS,
                           f"short read at {offset}: wanted {length}, got {end - offset}", where)
        return bytes(self._data[offset:end])

    def read_exact(self, offset: int, length: int, *, where: str = "") -> bytes | None:
        """Like :meth:`read` but returns None instead of a short buffer."""
        b = self.read(offset, length, where=where)
        return b if len(b) == length else None

    # -- little-endian scalar helpers -------------------------------------
    def u8(self, off: int) -> int:
        b = self.read(off, 1)
        return b[0] if b else 0

    def u16(self, off: int) -> int:
        b = self.read(off, 2)
        return struct.unpack_from("<H", b)[0] if len(b) == 2 else 0

    def u32(self, off: int) -> int:
        b = self.read(off, 4)
        return struct.unpack_from("<I", b)[0] if len(b) == 4 else 0

    def u64(self, off: int) -> int:
        b = self.read(off, 8)
        return struct.unpack_from("<Q", b)[0] if len(b) == 8 else 0
