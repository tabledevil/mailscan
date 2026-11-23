from __future__ import annotations

import mailbox
import os
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Iterable, Iterator

@dataclass
class MailRecord:
    raw: bytes
    source: str
    container: str
    index: int = 0
    mailbox_path: str = ""
    recovered: bool = False
    folder: str = ""
    error: str = ""
    state: str = ""          # PST/OST: live, deleted, orphan, carved, …
    provenance: str = ""     # PST/OST: btree, stale_page, free_space, …

    def parse(self):
        return BytesParser(policy=policy.default).parsebytes(self.raw)


def looks_like_pst(path: str, data: bytes | None = None) -> bool:
    """PST/OST/NST by extension or by the ``!BDN`` magic."""
    if path.lower().endswith((".pst", ".ost", ".nst")):
        return True
    if data is not None:
        return data.startswith(b"!BDN")
    try:
        with open(path, "rb") as handle:
            return handle.read(4) == b"!BDN"
    except OSError:
        return False


def looks_like_mbox(path: str) -> bool:
    if path.lower().endswith(".mbox"):
        return True
    try:
        with open(path, "rb") as handle:
            return handle.read(5) == b"From "
    except OSError:
        return False


def iter_mail_records(paths: Iterable[str], include_pst_recovered: bool = True) -> Iterator[MailRecord]:
    for input_path in paths:
        path = os.path.abspath(input_path)
        if os.path.isdir(path):
            for root, _dirs, files in os.walk(path):
                for name in sorted(files):
                    yield from iter_mail_records(
                        [os.path.join(root, name)],
                        include_pst_recovered=include_pst_recovered,
                    )
        elif looks_like_pst(path):
            yield from iter_pst(path, include_recovered=include_pst_recovered)
        elif looks_like_mbox(path):
            yield from iter_mbox(path)
        else:
            yield from iter_eml_file(path)


def iter_eml_file(path: str) -> Iterator[MailRecord]:
    try:
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as exc:
        yield MailRecord(raw=b"", source=path, container="file", mailbox_path=path, error=str(exc))
        return
    yield MailRecord(raw=data, source=path, container="file", mailbox_path=path)


def iter_mbox(path: str) -> Iterator[MailRecord]:
    try:
        box = mailbox.mbox(path, factory=None, create=False)
    except Exception as exc:
        yield MailRecord(raw=b"", source=path, container="mbox", mailbox_path=path, error=str(exc))
        return

    try:
        for idx, message in enumerate(box):
            try:
                try:
                    data = message.as_bytes(policy=policy.default)
                except Exception:
                    data = message.as_bytes()
                yield MailRecord(
                    raw=data,
                    source=f"{path}#{idx + 1}",
                    container="mbox",
                    index=idx + 1,
                    mailbox_path=path,
                )
            except Exception as exc:
                yield MailRecord(
                    raw=b"",
                    source=f"{path}#{idx + 1}",
                    container="mbox",
                    index=idx + 1,
                    mailbox_path=path,
                    error=str(exc),
                )
    finally:
        box.close()


def iter_pst(path: str, include_recovered: bool = True) -> Iterator[MailRecord]:
    """Every message of a PST/OST as an .eml record, via the native
    ``pstforensic`` reader (tolerant of damaged stores; deleted, orphaned,
    superseded and carved items included unless ``include_recovered`` is
    False).  The store is memory-mapped, never read whole."""
    try:
        from pstforensic import open_store
        from pstforensic.export import item_to_eml
    except ImportError as exc:  # pragma: no cover - ships with MATT
        yield MailRecord(raw=b"", source=path, container="pst", mailbox_path=path,
                         error=f"pstforensic unavailable: {exc}")
        return
    try:
        store = open_store(path)
    except Exception as exc:
        yield MailRecord(raw=b"", source=path, container="pst", mailbox_path=path,
                         error=f"not readable as PST/OST: {exc}")
        return
    index = 0
    for item in store.iter_items():
        recovered = item.state not in ("live", "live_damaged")
        if recovered and not include_recovered:
            continue
        index += 1
        folder = item.folder_label
        try:
            raw = item_to_eml(item)
        except Exception as exc:
            yield MailRecord(raw=b"", source=f"{path}#{index}", container="pst",
                             index=index, mailbox_path=path, recovered=recovered,
                             folder=folder, error=str(exc), state=item.state)
            continue
        if raw:
            yield MailRecord(raw=raw, source=f"{path}#{index}", container="pst",
                             index=index, mailbox_path=path, recovered=recovered,
                             folder=folder, state=item.state,
                             provenance=item.provenance)


def safe_filename(value: str) -> str:
    safe = "".join(c if c.isalnum() or c in ".-_ " else "_" for c in value).strip()
    safe = safe[:180].strip(" .")
    return safe or "message.eml"


def is_probably_email(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in {".eml", ".msg", ".txt", ""}
