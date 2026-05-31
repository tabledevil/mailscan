"""Thin CFBF/OLE wrapper over ``olefile`` for the MSG parser (PLAN §10.1).

A ``.msg`` file is a Compound File Binary Format container ([MS-CFB]).  We do
not re-implement CFB parsing; instead we wrap the optional :mod:`olefile`
dependency and expose a small, forensic-friendly surface:

  * list the storages (sub-directories) and streams at any path,
  * read a stream's bytes,
  * a stub :func:`CfbfContainer.orphan_storages` carve hook for *deleted*
    recipient/attachment storages that still live in the FAT free chain
    (recovery, PLAN §10.1 — TODO).

``olefile`` is import-guarded: importing this module never fails, but
constructing a :class:`CfbfContainer` without ``olefile`` installed raises
:class:`~pstforensic.exceptions.NotAMsgError` so the caller can degrade.
"""
from __future__ import annotations

import io
from typing import Iterator, Optional, Union

from ..exceptions import NotAMsgError, WarnCode, WarningSink

try:  # optional dependency (MATT ``office`` / ``msg`` extra)
    import olefile as _olefile

    _HAVE_OLEFILE = True
except Exception:  # pragma: no cover - exercised only when olefile absent
    _olefile = None
    _HAVE_OLEFILE = False

# CFBF signature ([MS-CFB] §2.2 Compound File Header, "Header Signature").
CFBF_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"

SourceLike = Union[str, bytes, bytearray, io.IOBase]


def have_olefile() -> bool:
    """Return whether the optional :mod:`olefile` dependency is importable."""
    return _HAVE_OLEFILE


def looks_like_cfbf(head: bytes) -> bool:
    """Return ``True`` if ``head`` starts with the CFBF magic ([MS-CFB] §2.2)."""
    return head[:8] == CFBF_MAGIC


class CfbfContainer:
    """A read-only view over a CFBF compound file backed by :mod:`olefile`.

    Paths are expressed as ``/``-joined storage names (case-insensitive, as the
    MSG spec keeps everything ASCII), mirroring ``olefile``'s list-of-segments
    addressing but in a string form that is convenient for the parser.

    Args:
        source: A path, a ``bytes`` image, or a seekable binary stream.
        sink: Optional warning sink for advisory anomalies.

    Raises:
        NotAMsgError: If :mod:`olefile` is unavailable or the bytes are not a
            recognisable compound file.
    """

    def __init__(self, source: SourceLike, *, sink: Optional[WarningSink] = None) -> None:
        self.sink = sink if sink is not None else WarningSink()
        if not _HAVE_OLEFILE:
            raise NotAMsgError("olefile is not installed; cannot parse MSG/CFBF")

        # Normalise to something olefile accepts (path or file-like).
        self._raw: Optional[bytes] = None
        if isinstance(source, (bytes, bytearray)):
            self._raw = bytes(source)
            fobj: object = io.BytesIO(self._raw)
        elif isinstance(source, str):
            with open(source, "rb") as fh:
                self._raw = fh.read()
            fobj = io.BytesIO(self._raw)
        else:
            # File-like: snapshot bytes so the orphan carve hook can scan them.
            cur = source.tell() if hasattr(source, "tell") else None
            try:
                source.seek(0)
                self._raw = source.read()
            except Exception:  # pragma: no cover - non-seekable stream
                self._raw = None
            finally:
                if cur is not None:
                    try:
                        source.seek(cur)
                    except Exception:
                        pass
            fobj = io.BytesIO(self._raw) if self._raw is not None else source

        if self._raw is not None and not looks_like_cfbf(self._raw):
            raise NotAMsgError("not a CFBF compound file (bad header signature)")

        try:
            self._ole = _olefile.OleFileIO(fobj)
        except Exception as exc:  # not a valid compound file
            raise NotAMsgError(f"olefile could not open compound file: {exc}") from exc

        # Pre-compute the directory listing as a set of normalised string paths.
        self._entries: list[list[str]] = self._ole.listdir(streams=True, storages=True)

    # -- introspection -----------------------------------------------------

    @staticmethod
    def _join(path: list[str]) -> str:
        return "/".join(path)

    @staticmethod
    def _split(path: str) -> list[str]:
        return [p for p in path.split("/") if p != ""]

    def streams(self, prefix: str = "") -> Iterator[str]:
        """Yield stream names directly inside the storage at ``prefix``.

        Args:
            prefix: ``/``-joined storage path ("" = root).

        Yields:
            The leaf stream name (not the full path) of each immediate child
            stream.
        """
        base = self._split(prefix)
        depth = len(base)
        for ent in self._entries:
            if len(ent) == depth + 1 and ent[:depth] == base:
                if self._ole.get_type(ent) == _olefile.STGTY_STREAM:
                    yield ent[-1]

    def storages(self, prefix: str = "") -> Iterator[str]:
        """Yield storage (sub-directory) names directly inside ``prefix``.

        Args:
            prefix: ``/``-joined storage path ("" = root).

        Yields:
            The leaf storage name of each immediate child storage.
        """
        base = self._split(prefix)
        depth = len(base)
        seen: set[str] = set()
        for ent in self._entries:
            if len(ent) > depth and ent[:depth] == base:
                name = ent[depth]
                if name in seen:
                    continue
                # A name is a storage if it has children OR is typed as storage.
                full = base + [name]
                try:
                    is_storage = self._ole.get_type(full) == _olefile.STGTY_STORAGE
                except Exception:
                    is_storage = len(ent) > depth + 1
                if is_storage or len(ent) > depth + 1:
                    seen.add(name)
                    yield name

    def has_stream(self, path: str) -> bool:
        """Return whether a stream exists at the ``/``-joined ``path``."""
        seg = self._split(path)
        return self._ole.exists(seg) and self._ole.get_type(seg) == _olefile.STGTY_STREAM

    def has_storage(self, path: str) -> bool:
        """Return whether a storage exists at the ``/``-joined ``path``."""
        seg = self._split(path)
        try:
            return self._ole.exists(seg) and self._ole.get_type(seg) == _olefile.STGTY_STORAGE
        except Exception:
            return False

    def read_stream(self, path: str) -> Optional[bytes]:
        """Read the full bytes of the stream at ``path``, or ``None`` if absent.

        Never raises on a missing/short stream; records an
        :data:`~pstforensic.exceptions.WarnCode.OUT_OF_BOUNDS` advisory instead.
        """
        seg = self._split(path)
        try:
            if not self._ole.exists(seg):
                return None
            with self._ole.openstream(seg) as st:
                return st.read()
        except Exception as exc:
            self.sink.warn(WarnCode.OUT_OF_BOUNDS, f"stream read failed: {exc}", where=path)
            return None

    def raw_bytes(self) -> Optional[bytes]:
        """Return the full file image if known (used by the carve hook)."""
        return self._raw

    # -- recovery ----------------------------------------------------------

    def orphan_storages(self) -> list[dict]:
        """Carve hook for deleted recipient/attachment storages (PLAN §10.1).

        Outlook frees a directory entry on delete by zeroing its name and
        re-coloring it, but the underlying mini/FAT chains often survive in the
        free list.  A full implementation walks the raw CFB FAT for sectors not
        referenced by any live directory entry and re-assembles ``__recip_*`` /
        ``__attach_*`` storages from the slack.

        Returns:
            A list of carved-storage descriptors.  Currently always empty.

        .. todo:: Implement free-FAT-sector carving over :meth:`raw_bytes`.
        """
        # TODO(recovery): scan self._raw for orphaned directory entries whose
        # name was zeroed but whose start-sector chain is intact, then expose
        # them as pseudo-storages.  Requires a from-scratch CFB FAT walker that
        # does not rely on olefile's live-tree view.
        return []

    def close(self) -> None:
        """Release the underlying :mod:`olefile` handle."""
        try:
            self._ole.close()
        except Exception:  # pragma: no cover
            pass

    def __enter__(self) -> "CfbfContainer":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
