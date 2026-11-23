"""pstforensic.export — MAPI message → .eml."""
from datetime import datetime, timezone
from email import policy
from email.parser import BytesParser

from pstforensic.export import message_to_eml


class _Obj:
    def __init__(self, props=None, **kw):
        self.props = props or {}
        self.__dict__.update(kw)

    def render(self, pid):
        return self.props.get(pid)

    def raw_of(self, pid):
        v = self.props.get(pid)
        return v if isinstance(v, (bytes, bytearray)) else None


def _parse(raw):
    return BytesParser(policy=policy.default).parsebytes(raw)


def _msg(props=None, recipients=(), attachments=()):
    return _Obj(props or {}, recipients=list(recipients), attachments=list(attachments))


def test_transport_headers_win_and_missing_ones_are_synthesized():
    hdrs = ("Received: from mx.example ([192.0.2.1]) by mail.example; Tue, 1 Jun 2021 10:00:00 +0000\r\n"
            "Authentication-Results: mail.example; spf=fail smtp.mailfrom=evil.example\r\n"
            "Message-ID: <abc@evil.example>\r\nContent-Type: text/html\r\n\r\n")
    m = _msg({0x007D: hdrs, 0x0037: "Hi", 0x0C1A: "Eve", 0x5D01: "eve@evil.example",
              0x1000: "body",
              0x0039: datetime(2021, 6, 1, 10, 0, tzinfo=timezone.utc)},
             recipients=[_Obj({0x3001: "Bob", 0x39FE: "bob@example.com"}, recipient_type=1),
                         _Obj({0x3001: "Carol", 0x3003: "carol@example.com"}, recipient_type=3)])
    e = _parse(message_to_eml(m, folder="/Top/Inbox", state="live", provenance="btree"))
    assert str(e["Received"]).strip().startswith("from mx.example")
    assert "spf=fail" in e["Authentication-Results"]
    assert e["Message-ID"] == "<abc@evil.example>"
    assert e["Subject"] == "Hi" and e["From"].addresses[0].addr_spec == "eve@evil.example"
    assert e["To"].addresses[0].addr_spec == "bob@example.com"
    assert e["Bcc"].addresses[0].addr_spec == "carol@example.com"
    assert e["Date"].datetime.year == 2021
    assert e.get_content_type() == "text/plain"      # original Content-Type not kept
    assert e["X-MATT-PST-Folder"] == "/Top/Inbox" and "X-MATT-PST-Recovered" not in e


def test_html_alternative_and_attachments_and_references():
    att = _Obj({0x3707: "a.pdf", 0x370E: "application/pdf", 0x3712: "img1"},
               method=1, open_data=lambda: b"%PDF-1.7")
    ref = _Obj({0x3707: "share.docx", 0x370D: "\\\\srv\\share\\share.docx"}, method=2)
    m = _msg({0x0037: "S", 0x1000: "plain", 0x1013: "<p>html</p>"}, attachments=[att, ref])
    e = _parse(message_to_eml(m))
    body = e.get_body(("html",))
    assert "<p>html</p>" in body.get_content()
    parts = list(e.iter_attachments())
    assert [p.get_filename() for p in parts] == ["a.pdf"]
    assert parts[0].get_content_type() == "application/pdf"
    assert parts[0]["Content-ID"] == "<img1>"
    assert "srv" in e["X-MATT-Attachment-Reference"]


def test_embedded_message_is_message_rfc822():
    inner = _msg({0x0037: "Inner", 0x1000: "inner body"})
    m = _msg({0x0037: "Outer", 0x1000: "x"},
             attachments=[_Obj({0x3707: "fwd.msg"}, method=5, embedded=inner)])
    e = _parse(message_to_eml(m))
    part = next(e.iter_attachments())
    assert part.get_content_type() == "message/rfc822"
    assert part.get_content()["Subject"] == "Inner"


def test_rtf_only_body_is_attached_and_recovered_state_marked():
    import struct
    rtf = b"{\\rtf1 hello}"
    blob = struct.pack("<IIII", len(rtf) + 12, len(rtf), 0x414C454D, 0) + rtf   # MELA = uncompressed
    m = _msg({0x0037: "R", 0x1009: blob})
    e = _parse(message_to_eml(m, state="carved", findings=["SUBNODES_UNKNOWN"]))
    names = [p.get_filename() for p in e.iter_attachments()]
    assert names == ["body.rtf"]
    assert e["X-MATT-PST-Recovered"] == "true"
    assert e["X-MATT-PST-Findings"] == "SUBNODES_UNKNOWN"


def test_damaged_message_never_raises():
    class Broken(_Obj):
        def render(self, pid):
            raise ValueError("bad")
    bad_att = _Obj({}, method=1, open_data=lambda: (_ for _ in ()).throw(OSError("gone")))
    m = Broken({}, recipients=[], attachments=[bad_att])
    e = _parse(message_to_eml(m, state="lost"))
    assert e["X-MATT-PST-State"] == "lost"
