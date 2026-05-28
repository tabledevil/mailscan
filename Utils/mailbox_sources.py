from __future__ import annotations

from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
import mailbox
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable, Iterator, Optional

try:
    import pypff
except ImportError:
    pypff = None


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

    def parse(self):
        return BytesParser(policy=policy.default).parsebytes(self.raw)


def looks_like_pst(path: str, data: bytes | None = None) -> bool:
    if path.lower().endswith(".pst"):
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
    pypff_error = None
    if pypff is not None:
        pst = pypff.file()
        try:
            pst.open(path)
            root = pst.get_root_folder()
            counter = {"index": 0}
            yielded = False
            for record in _iter_pst_folder(root, path, [], counter, recovered=False):
                yielded = True
                yield record
            if include_recovered:
                for label in ("orphan", "recovered"):
                    for item in _iter_pst_store_items(pst, label):
                        for record in _iter_pst_item(item, path, [f"$PST-{label}"], counter, recovered=True):
                            yielded = True
                            yield record
            if yielded:
                return
        except Exception as exc:
            pypff_error = str(exc)
        finally:
            try:
                pst.close()
            except Exception:
                pass
    else:
        pypff_error = "pypff/libpff Python bindings are not installed"

    fallback_yielded = False
    for record in iter_pffexport(path, include_recovered=include_recovered):
        fallback_yielded = True
        yield record

    if not fallback_yielded:
        yield MailRecord(
            raw=b"",
            source=path,
            container="pst",
            mailbox_path=path,
            error=pypff_error or "PST parser could not extract messages",
        )


def iter_pffexport(path: str, include_recovered: bool = True) -> Iterator[MailRecord]:
    if not shutil.which("pffexport"):
        return

    with tempfile.TemporaryDirectory(prefix="matt_pffexport_") as tmpdir:
        target = os.path.join(tmpdir, "pst")
        mode = "all" if include_recovered else "items"
        proc = subprocess.run(
            ["pffexport", "-q", "-f", "all", "-m", mode, "-t", target, path],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            message = (proc.stderr or proc.stdout or "pffexport failed").strip()
            yield MailRecord(raw=b"", source=path, container="pst", mailbox_path=path, error=message)
            return

        index = 0
        for root, _dirs, files in os.walk(tmpdir):
            recovered = any(part.endswith((".orphans", ".recovered")) for part in root.split(os.sep))
            for name in sorted(files):
                file_path = os.path.join(root, name)
                if not os.path.isfile(file_path) or os.path.getsize(file_path) == 0:
                    continue
                lower = name.lower()
                if lower.endswith((".eml", ".txt", ".html", ".rtf")):
                    try:
                        raw = _exported_file_to_eml(file_path)
                    except OSError as exc:
                        index += 1
                        yield MailRecord(raw=b"", source=file_path, container="pst", index=index, mailbox_path=path, recovered=recovered, error=str(exc))
                        continue
                    index += 1
                    yield MailRecord(
                        raw=raw,
                        source=file_path,
                        container="pst-pffexport",
                        index=index,
                        mailbox_path=path,
                        recovered=recovered,
                        folder=os.path.relpath(root, tmpdir),
                    )


def _exported_file_to_eml(path: str) -> bytes:
    with open(path, "rb") as handle:
        data = handle.read()
    lower = path.lower()
    if lower.endswith(".eml"):
        return data
    msg = EmailMessage(policy=policy.default)
    msg["Subject"] = os.path.basename(path)
    msg["X-MATT-PST-Exported-File"] = path
    if lower.endswith(".html"):
        msg.set_content("")
        msg.add_alternative(data.decode("utf-8", errors="replace"), subtype="html")
    elif lower.endswith(".rtf"):
        msg.set_content("")
        msg.add_attachment(data, maintype="application", subtype="rtf", filename=os.path.basename(path))
    else:
        msg.set_content(data.decode("utf-8", errors="replace"))
    return msg.as_bytes(policy=policy.default)


def _safe_attr(obj, name, default=None):
    try:
        return getattr(obj, name)
    except Exception:
        return default


def _safe_text(value) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _iter_pst_folder(folder, pst_path: str, path_parts: list[str], counter: dict, recovered: bool):
    folder_name = _safe_text(_safe_attr(folder, "name", None))
    current_path = path_parts + ([folder_name] if folder_name else [])

    for idx in range(_safe_attr(folder, "number_of_sub_messages", 0) or 0):
        try:
            message = folder.get_sub_message(idx)
            yield _pst_message_record(message, pst_path, current_path, counter, recovered=recovered)
        except Exception as exc:
            counter["index"] += 1
            yield MailRecord(
                raw=b"",
                source=f"{pst_path}#{counter['index']}",
                container="pst",
                index=counter["index"],
                mailbox_path=pst_path,
                recovered=recovered,
                folder="/".join(current_path),
                error=str(exc),
            )

    for idx in range(_safe_attr(folder, "number_of_sub_folders", 0) or 0):
        try:
            yield from _iter_pst_folder(folder.get_sub_folder(idx), pst_path, current_path, counter, recovered=recovered)
        except Exception as exc:
            counter["index"] += 1
            yield MailRecord(
                raw=b"",
                source=f"{pst_path}#{counter['index']}",
                container="pst",
                index=counter["index"],
                mailbox_path=pst_path,
                recovered=recovered,
                folder="/".join(current_path),
                error=str(exc),
            )


def _iter_pst_store_items(pst, label: str):
    count_names = (
        f"number_of_{label}_items",
        f"get_number_of_{label}_items",
        f"number_of_{label}_folders",
        f"get_number_of_{label}_folders",
    )
    getter_names = (f"get_{label}_item", f"get_{label}_folder")

    count = None
    for name in count_names:
        value = _safe_attr(pst, name, None)
        if callable(value):
            try:
                value = value()
            except Exception:
                continue
        if isinstance(value, int):
            count = value
            break

    if count is not None:
        for idx in range(count):
            for getter_name in getter_names:
                getter = _safe_attr(pst, getter_name, None)
                if not callable(getter):
                    continue
                try:
                    yield getter(idx)
                    break
                except Exception:
                    continue
        return

    for attr in (f"{label}_items", f"{label}_folders"):
        items = _safe_attr(pst, attr, None)
        if items is None:
            continue
        try:
            yield from items
        except TypeError:
            continue


def _iter_pst_item(item, pst_path: str, path_parts: list[str], counter: dict, recovered: bool):
    if _looks_like_folder(item):
        yield from _iter_pst_folder(item, pst_path, path_parts, counter, recovered=recovered)
    elif _looks_like_message(item):
        try:
            yield _pst_message_record(item, pst_path, path_parts, counter, recovered=recovered)
        except Exception as exc:
            counter["index"] += 1
            yield MailRecord(
                raw=b"",
                source=f"{pst_path}#{counter['index']}",
                container="pst",
                index=counter["index"],
                mailbox_path=pst_path,
                recovered=recovered,
                folder="/".join(path_parts),
                error=str(exc),
            )


def _looks_like_folder(item) -> bool:
    return any(_safe_attr(item, attr, None) is not None for attr in ("number_of_sub_messages", "number_of_sub_folders"))


def _looks_like_message(item) -> bool:
    return any(_safe_attr(item, attr, None) is not None for attr in ("subject", "plain_text_body", "html_body", "transport_headers"))


def _pst_message_record(message, pst_path: str, folder_parts: list[str], counter: dict, recovered: bool) -> MailRecord:
    counter["index"] += 1
    raw = pst_message_to_eml(message, folder="/".join(folder_parts), recovered=recovered)
    subject = _safe_text(_safe_attr(message, "subject", None)) or "message"
    return MailRecord(
        raw=raw,
        source=f"{pst_path}#{counter['index']}:{subject}",
        container="pst",
        index=counter["index"],
        mailbox_path=pst_path,
        recovered=recovered,
        folder="/".join(folder_parts),
    )


def pst_message_to_eml(message, folder: str = "", recovered: bool = False) -> bytes:
    headers = _safe_attr(message, "transport_headers", None)
    msg = _message_from_headers(headers) or EmailMessage(policy=policy.default)

    _set_header_if_missing(msg, "Subject", _safe_attr(message, "subject", None))
    _set_header_if_missing(msg, "From", _sender(message))
    _set_header_if_missing(msg, "To", _safe_attr(message, "display_to", None))
    _set_header_if_missing(msg, "Cc", _safe_attr(message, "display_cc", None))
    _set_header_if_missing(msg, "Bcc", _safe_attr(message, "display_bcc", None))
    _set_header_if_missing(msg, "Date", _safe_attr(message, "delivery_time", None))
    if folder and "X-MATT-PST-Folder" not in msg:
        msg["X-MATT-PST-Folder"] = folder
    if recovered and "X-MATT-PST-Recovered" not in msg:
        msg["X-MATT-PST-Recovered"] = "true"

    body = _safe_attr(message, "plain_text_body", None)
    html = _safe_attr(message, "html_body", None)
    rtf = _safe_attr(message, "rtf_body", None)

    if body:
        msg.set_content(_safe_text(body) or "")
    elif not msg.is_multipart():
        msg.set_content("")
    if html:
        msg.add_alternative(_safe_text(html) or "", subtype="html")
    if rtf:
        try:
            msg.add_attachment(rtf, maintype="application", subtype="rtf", filename="body.rtf")
        except Exception:
            pass

    for idx in range(_safe_attr(message, "number_of_attachments", 0) or 0):
        try:
            attachment = message.get_attachment(idx)
            data = _read_pst_attachment(attachment)
            if data is None:
                continue
            msg.add_attachment(
                data,
                maintype="application",
                subtype="octet-stream",
                filename=_attachment_filename(attachment, idx),
            )
        except Exception:
            continue
    return msg.as_bytes(policy=policy.default)


def _message_from_headers(headers):
    if not headers:
        return None
    if isinstance(headers, str):
        headers = headers.encode("utf-8", errors="replace")
    try:
        return BytesParser(policy=policy.default).parsebytes(headers)
    except Exception:
        return None


def _sender(message):
    email = _safe_text(_safe_attr(message, "sender_email_address", None))
    name = _safe_text(_safe_attr(message, "sender_name", None))
    if name and email:
        return f"{name} <{email}>"
    return email or name


def _set_header_if_missing(msg, name: str, value) -> None:
    if name in msg or value in (None, ""):
        return
    text = _safe_text(value)
    if not text:
        return
    try:
        msg[name] = " ".join(text.splitlines())
    except Exception:
        pass


def _read_pst_attachment(attachment):
    size = _safe_attr(attachment, "size", 0) or 0
    if hasattr(attachment, "read_buffer"):
        try:
            return attachment.read_buffer(size)
        except TypeError:
            chunks = []
            while True:
                chunk = attachment.read_buffer(1024 * 1024)
                if not chunk:
                    break
                chunks.append(chunk)
            return b"".join(chunks)
        except Exception:
            return None
    data = _safe_attr(attachment, "data", None)
    return data if isinstance(data, bytes) else None


def _attachment_filename(attachment, idx: int) -> str:
    for attr in ("long_filename", "filename", "name"):
        value = _safe_text(_safe_attr(attachment, attr, None))
        if value:
            return safe_filename(value)
    return f"pst-attachment-{idx + 1}.bin"


def safe_filename(value: str) -> str:
    safe = "".join(c if c.isalnum() or c in ".-_ " else "_" for c in value).strip()
    safe = safe[:180].strip(" .")
    return safe or "message.eml"


def is_probably_email(path: str) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in {".eml", ".msg", ".txt", ""}
