"""Field-test regressions: capability notes once per run, not per object;
DOC variants reach a real analyzer instead of the generic fallback."""

import base64
import os
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Analyzer, Structure
from Utils import capabilities
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    capabilities.reset()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()
    capabilities.reset()


def _ole() -> bytes:
    from pstforensic.tests.synth import _write_cfbf_minimal
    return _write_cfbf_minimal({"WordDocument": b"\xec\xa5\xc1\x00" + b"\x00" * 508})


def _primary(data, filename="x.doc", mime_type=None):
    s = Structure.create(data=data, filename=filename, mime_type=mime_type)
    return s, type(s.analyzer).__name__


# -- DOC dispatch ----------------------------------------------------------
@pytest.mark.parametrize("filename,mime,expected", [
    ("x.doc", None, "OLEOfficeAnalyzer"),
    (None, None, "OLEOfficeAnalyzer"),
    ("x.doc", "application/vnd.ms-office", "OLEOfficeAnalyzer"),
    ("x.doc", "application/octet-stream", "OLEOfficeAnalyzer"),
])
def test_ole_doc_variants(filename, mime, expected):
    _s, name = _primary(_ole(), filename, mime)
    assert name == expected


def test_rtf_declared_as_msword_goes_to_rtf():
    s, name = _primary(b"{\\rtf1\\ansi Hello}", mime_type="application/msword")
    assert name == "RTFAnalyzer"
    assert "error" not in s.analyzer.reports      # no OLE parse failure merged in


def test_rtf_minimal_prefix_is_rtf():
    # Word accepts "{\rt" — maldocs drop the rest of the magic.
    _s, name = _primary(b"{\\rtx\\ansi Hello}", mime_type="application/octet-stream")
    assert name == "RTFAnalyzer"


def test_html_declared_as_msword_redispatched():
    s, name = _primary(b"<html><body><p>Hi</p></body></html>",
                       mime_type="application/msword")
    assert name == "HTMLAnalyzer"
    rep = s.analyzer.reports["declared_type_mismatch"]
    assert rep.data["declared"] == "application/msword"


def test_mht_saved_as_doc_is_parsed_as_mime():
    mht = (b"MIME-Version: 1.0\r\nContent-Type: multipart/related; boundary=\"b\"\r\n\r\n"
           b"--b\r\nContent-Type: text/html\r\n\r\n<html><body>hi</body></html>\r\n--b--\r\n")
    s, name = _primary(mht)
    assert name == "EmailAnalyzer"
    assert any(c.mime_type == "text/html" for c in s.get_children())


def test_quoted_mail_in_text_is_not_mht():
    text = b"Hello,\n\nsee below\n\nMIME-Version: 1.0\nContent-Type: multipart/related\n"
    _s, name = _primary(text, filename="note.txt", mime_type="text/plain")
    assert name != "EmailAnalyzer"


def test_word2003_xml_with_activemime_macros():
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64
    mso = b"ActiveMime" + b"\x00" * (0x32 - 10) + zlib.compress(ole)
    doc = (b'<?xml version="1.0"?>\n<?mso-application progid="Word.Document"?>\n'
           b'<w:wordDocument xmlns:w="http://schemas.microsoft.com/office/word/2003/wordml">'
           b'<w:binData w:name="editdata.mso">' + base64.b64encode(mso) +
           b'</w:binData><w:body/></w:wordDocument>')
    s, name = _primary(doc)
    assert name == "OfficeXMLAnalyzer"
    assert "flat_office_xml_macros" in s.analyzer.reports
    kids = s.get_children()
    assert kids and kids[0].rawdata.startswith(b"\xd0\xcf\x11\xe0")


# -- capabilities ----------------------------------------------------------
def test_missing_analyzer_is_noted_on_object_and_counted_at_root(monkeypatch):
    from Analyzers.OLEOfficeAnalyzer import OLEOfficeAnalyzer
    monkeypatch.setattr(OLEOfficeAnalyzer, "is_available",
                        classmethod(lambda cls: (False, "Missing pip dependency: olefile")))
    capabilities.reset()
    s, name = _primary(_ole())
    assert name == "Analyzer"
    lim = s.analyzer.reports["analysis_limited"]
    assert lim.verbosity >= 1 and lim.data[0]["analyzer"] == "OLEOfficeAnalyzer"
    cap = s.analyzer.reports["capabilities"]
    assert cap.verbosity == 0
    assert cap.data["analyzers"][0]["objects"] == 1
    assert "olefile" in cap.text


def test_missing_mime_providers_not_reported_per_object(monkeypatch):
    monkeypatch.setattr(capabilities, "provider_status", lambda: {
        "python_magic": {"provider": "python_magic", "available": False,
                         "reason": "python-magic is not installed"},
        "file_command": {"provider": "file_command", "available": True, "reason": ""},
        "magika": {"provider": "magika", "available": False,
                   "reason": "magika is not installed"},
    })
    from Utils.filetype import detect_all_providers
    dets = detect_all_providers(b"hello world\n", filename="a.txt")
    assert [d["provider"] for d in dets] == ["file_command"]
    s = Structure.create(data=b"From: a@x.example\r\nSubject: t\r\n\r\nbody\n",
                         filename="t.eml", mime_type="message/rfc822")
    cap = s.analyzer.reports["capabilities"]
    assert "python-magic is not installed" in cap.text and cap.verbosity == 1


def test_detect_all_providers_reads_head_of_large_input(monkeypatch):
    from Config.config import flags
    from Utils import filetype
    seen = []

    class _P:
        def detect(self, data, filename=None):
            seen.append(len(data))
            return filetype.DetectionResult(mime="application/octet-stream",
                                            description="", provider="probe")
    monkeypatch.setattr(flags, "large_file_threshold", 1024)
    monkeypatch.setitem(filetype._PROVIDERS, "file_command", _P())
    monkeypatch.setattr(filetype, "_resolve_provider_order", lambda: ["file_command"])
    filetype.detect_all_providers(b"\x00" * (3 << 20))
    assert seen == [1 << 20]


def test_warn_once(monkeypatch):
    seen = []
    monkeypatch.setattr(capabilities.log, "warning", lambda msg, *a: seen.append(msg))
    for _ in range(5):
        capabilities.warn_once("k", "dependency X missing")
    assert seen == ["dependency X missing"]


def test_text_renderer_keeps_report_line_breaks():
    from Analyzers.OLEOfficeAnalyzer import OLEOfficeAnalyzer
    import pytest as _pt
    mp = _pt.MonkeyPatch()
    mp.setattr(OLEOfficeAnalyzer, "is_available",
               classmethod(lambda cls: (False, "Missing pip dependency: olefile")))
    capabilities.reset()
    try:
        s = Structure.create(data=_ole(), filename="x.doc")
        out = s.get_report(report_format="text", verbosity=0)
    finally:
        mp.undo()
    cap = [l for l in out.splitlines() if "capabilities :" in l]
    assert cap and "OLEOfficeAnalyzer" in cap[0]
    assert "MIME detection" not in cap[0] or len(cap[0]) < 140


def test_generic_declared_type_is_not_a_mismatch():
    # PST/MIME attachments without a type are declared octet-stream: content
    # decides the analyzer, but that is no contradiction worth a finding.
    s, _name = _primary(b"{\\rtf1\\ansi Hello}", filename="x.rtf",
                        mime_type="application/octet-stream")
    assert "declared_type_mismatch" not in s.analyzer.reports
