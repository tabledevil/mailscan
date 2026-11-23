"""MAPI message → RFC 5322 / MIME (``.eml``) — so mail tooling that speaks
MIME (MATT's EmailAnalyzer, the leak pipeline, mail clients) sees a PST/OST
or MSG message with its headers, bodies, attachments and embedded messages.

Fidelity rules:

* The original **transport headers** (``PidTagTransportMessageHeaders``) are
  the header block when present — Received chain, authentication results,
  Message-ID survive.  Headers missing there are synthesized from MAPI
  properties (Subject, From, To/Cc/Bcc from the recipient table, Date,
  Message-ID, In-Reply-To).
* Bodies: plain text and HTML as ``multipart/alternative``; the compressed
  RTF body is decompressed and attached as ``body.rtf`` when neither plain
  nor HTML exists.
* Attachments: by value (method 1) with their file name, MIME tag and
  Content-ID; embedded messages (method 5) recursively as ``message/rfc822``;
  OLE objects (6) as ``application/octet-stream``; by-reference attachments
  (2/3/4/7) have no bytes in the store and are listed in
  ``X-MATT-Attachment-Reference`` headers instead of being dropped.
* Forensic context goes into ``X-MATT-PST-*`` headers: folder, state,
  provenance, integrity finding codes (``X-MATT-PST-Recovered: true`` for
  everything that is not a live item).

Never raises for a damaged message: whatever can be read is exported.
"""
from __future__ import annotations

import email.utils
from datetime import datetime
from email import policy
from email.message import EmailMessage
from email.parser import HeaderParser
from typing import Iterable, Optional

PID_SUBJECT = 0x0037
PID_TRANSPORT_HEADERS = 0x007D
PID_SENDER_NAME = 0x0C1A
PID_SENDER_EMAIL = 0x0C1F
PID_SENDER_SMTP = 0x5D01
PID_SENT_REPR_NAME = 0x0042
PID_SENT_REPR_EMAIL = 0x0065
PID_SENT_REPR_SMTP = 0x5D02
PID_DISPLAY_TO, PID_DISPLAY_CC, PID_DISPLAY_BCC = 0x0E04, 0x0E03, 0x0E02
PID_CLIENT_SUBMIT_TIME = 0x0039
PID_DELIVERY_TIME = 0x0E06
PID_MESSAGE_ID = 0x1035
PID_IN_REPLY_TO = 0x1042
PID_BODY = 0x1000
PID_BODY_HTML = 0x1013
PID_RTF_COMPRESSED = 0x1009
PID_INTERNET_CPID = 0x3FDE
# recipients
PID_DISPLAY_NAME = 0x3001
PID_EMAIL_ADDRESS = 0x3003
PID_SMTP_ADDRESS = 0x39FE
# attachments
PID_ATTACH_LONG_FILENAME = 0x3707
PID_ATTACH_FILENAME = 0x3704
PID_ATTACH_MIME_TAG = 0x370E
PID_ATTACH_CONTENT_ID = 0x3712
PID_ATTACH_PATHNAME = 0x370D
PID_ATTACH_LONG_PATHNAME = 0x3708

_REFERENCE_METHODS = {2: "by reference", 3: "by reference (resolve)",
                      4: "by reference (only)", 7: "web reference"}
_SYNTH_HEADERS = ("Subject", "From", "To", "Cc", "Bcc", "Date", "Message-ID",
                  "In-Reply-To")


def _str(obj, pid) -> Optional[str]:
    try:
        v = obj.render(pid)
    except Exception:
        return None
    if isinstance(v, bytes):
        return None
    return v.strip() if isinstance(v, str) and v.strip() else None


def _clean(value: str) -> str:
    """Header values must be single-line."""
    return " ".join(str(value).split())


def _addr(name: Optional[str], address: Optional[str]) -> Optional[str]:
    if address and "@" in address:
        return email.utils.formataddr((name or "", address))
    if name or address:
        return _clean(name or address)
    return None


def _sender(msg) -> Optional[str]:
    return (_addr(_str(msg, PID_SENT_REPR_NAME),
                  _str(msg, PID_SENT_REPR_SMTP) or _str(msg, PID_SENT_REPR_EMAIL))
            or _addr(_str(msg, PID_SENDER_NAME),
                     _str(msg, PID_SENDER_SMTP) or _str(msg, PID_SENDER_EMAIL)))


def _recipients(msg, rtype: int) -> list[str]:
    out = []
    for r in getattr(msg, "recipients", None) or []:
        if (getattr(r, "recipient_type", None) or 1) != rtype:
            continue
        a = _addr(_str(r, PID_DISPLAY_NAME),
                  _str(r, PID_SMTP_ADDRESS) or _str(r, PID_EMAIL_ADDRESS))
        if a:
            out.append(a)
    return out


def _date(msg) -> Optional[str]:
    for pid in (PID_CLIENT_SUBMIT_TIME, PID_DELIVERY_TIME):
        try:
            v = msg.render(pid)
        except Exception:
            continue
        if isinstance(v, datetime):
            try:
                return email.utils.format_datetime(v)
            except (ValueError, OverflowError):
                continue
    return None


def _set(m: EmailMessage, name: str, value) -> None:
    if value and _clean(value) and name not in m:
        try:
            m[name] = _clean(value)
        except Exception:           # malformed value: keep the message
            pass


def _html_text(msg) -> Optional[str]:
    v = None
    try:
        v = msg.render(PID_BODY_HTML)
    except Exception:
        pass
    if isinstance(v, str) and v.strip():
        return v
    raw = msg.raw_of(PID_BODY_HTML)
    if not raw:
        return None
    cp = None
    try:
        cpv = msg.raw_of(PID_INTERNET_CPID)
        cp = int.from_bytes(cpv[:4], "little") if cpv else None
    except Exception:
        pass
    from .render.strings import codepage_to_codec
    codec = (codepage_to_codec(cp) if cp else None) or "utf-8"
    try:
        return bytes(raw).decode(codec, "replace")
    except LookupError:
        return bytes(raw).decode("utf-8", "replace")


def _rtf(msg) -> Optional[bytes]:
    raw = msg.raw_of(PID_RTF_COMPRESSED)
    if not raw:
        return None
    try:
        from .render.rtf import decompress_rtf
        return decompress_rtf(bytes(raw)) or None
    except Exception:
        return None


def _attachment_name(att, idx: int) -> str:
    name = _str(att, PID_ATTACH_LONG_FILENAME) or _str(att, PID_ATTACH_FILENAME)
    return name or f"attachment_{idx}.bin"


def _add_attachments(m: EmailMessage, msg, depth: int) -> None:
    refs = []
    for idx, att in enumerate(getattr(msg, "attachments", None) or []):
        try:
            method = getattr(att, "method", None)
            name = _attachment_name(att, idx)
            if method == 5 and getattr(att, "embedded", None) is not None and depth < 8:
                inner = message_to_email(att.embedded, _depth=depth + 1)
                m.add_attachment(inner, filename=name)   # message/rfc822
                continue
            if method in _REFERENCE_METHODS:
                path = _str(att, PID_ATTACH_LONG_PATHNAME) or _str(att, PID_ATTACH_PATHNAME)
                refs.append(f"{name}; {_REFERENCE_METHODS[method]}"
                            + (f"; {path}" if path else ""))
                continue
            data = att.open_data() if callable(getattr(att, "open_data", None)) else None
            if not data:
                continue
            ctype = (_str(att, PID_ATTACH_MIME_TAG) or "application/octet-stream").lower()
            maintype, _, subtype = ctype.partition("/")
            if not subtype or maintype in ("multipart", "message"):
                maintype, subtype = "application", "octet-stream"
            cid = _str(att, PID_ATTACH_CONTENT_ID)
            kw = {"cid": f"<{cid.strip('<>')}>"} if cid else {}
            m.add_attachment(bytes(data), maintype=maintype, subtype=subtype,
                             filename=name, **kw)
        except Exception:
            continue
    for r in refs:
        m["X-MATT-Attachment-Reference"] = _clean(r)


def message_to_email(msg, *, folder: Optional[str] = None, state: Optional[str] = None,
                     provenance: Optional[str] = None,
                     findings: Iterable[str] = (), _depth: int = 0) -> EmailMessage:
    """Build an :class:`email.message.EmailMessage` from a MAPI message."""
    m = EmailMessage(policy=policy.default)
    headers = _str(msg, PID_TRANSPORT_HEADERS)
    if headers:
        try:
            # compat32 keeps raw values; unfold, keep order and duplicates
            # (every Received hop).
            parsed = HeaderParser(policy=policy.compat32).parsestr(headers)
            for k, v in parsed.raw_items():
                if k.lower() in ("content-type", "content-transfer-encoding",
                                 "mime-version"):
                    continue          # our MIME structure replaces the original
                try:
                    m[k] = _clean(v)
                except Exception:
                    continue
        except Exception:
            pass
    subject = _str(msg, PID_SUBJECT)
    _set(m, "Subject", subject)
    _set(m, "From", _sender(msg))
    for hdr, rtype, disp in (("To", 1, PID_DISPLAY_TO), ("Cc", 2, PID_DISPLAY_CC),
                             ("Bcc", 3, PID_DISPLAY_BCC)):
        _set(m, hdr, ", ".join(_recipients(msg, rtype)) or _str(msg, disp))
    _set(m, "Date", _date(msg))
    _set(m, "Message-ID", _str(msg, PID_MESSAGE_ID))
    _set(m, "In-Reply-To", _str(msg, PID_IN_REPLY_TO))
    if folder:
        m["X-MATT-PST-Folder"] = _clean(folder)
    if state:
        m["X-MATT-PST-State"] = state
        if state not in ("live", "live_damaged"):
            m["X-MATT-PST-Recovered"] = "true"
    if provenance:
        m["X-MATT-PST-Provenance"] = provenance
    codes = sorted(set(findings or ()))
    if codes:
        m["X-MATT-PST-Findings"] = ", ".join(codes)

    plain = _str(msg, PID_BODY)
    html = _html_text(msg)
    if plain is None and html is None:
        rtf = _rtf(msg)
        m.set_content("")
        if rtf:
            m.add_attachment(rtf, maintype="application", subtype="rtf", filename="body.rtf")
    else:
        m.set_content(plain or "")
        if html:
            m.add_alternative(html, subtype="html")
    _add_attachments(m, msg, _depth)
    return m


def message_to_eml(msg, **kw) -> bytes:
    """``message_to_email(...)`` serialized as RFC 5322 bytes."""
    return message_to_email(msg, **kw).as_bytes(policy=policy.default)


def item_to_eml(item) -> Optional[bytes]:
    """An inventory :class:`~pstforensic.messaging.inventory.Item` as
    ``.eml`` bytes with its folder, state, provenance and findings."""
    if getattr(item, "message", None) is None:
        return None
    return message_to_eml(item.message, folder=item.folder_label, state=item.state,
                          provenance=item.provenance,
                          findings=getattr(item.integrity, "codes", ()))
