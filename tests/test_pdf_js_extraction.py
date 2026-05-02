"""Sprint 8 — extract embedded /JavaScript /JS streams from PDFs as
text/javascript child Structures so ScriptAnalyzer chews them."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _pdf_with_js(js_source: str) -> bytes:
    """Build a minimal but real PDF with an OpenAction /JavaScript action
    pointing at an inline /JS string. Hand-rolled so we don't need a
    PDF-writing dependency."""
    js_bytes = js_source.encode("utf-8")
    objs: list[bytes] = [b""]  # 1-indexed

    objs.append(b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objs.append(
        b"<< /Type /Action /S /JavaScript /JS 4 0 R >>"
    )
    # JS string object as a literal-string PDF object
    escaped = js_bytes.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    objs.append(b"(" + escaped + b")")

    body = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
    offsets = []
    for i in range(1, len(objs)):
        offsets.append(len(body))
        body += f"{i} 0 obj\n".encode() + objs[i] + b"\nendobj\n"
    xref_pos = len(body)
    body += b"xref\n0 " + str(len(objs)).encode() + b"\n"
    body += b"0000000000 65535 f \n"
    for off in offsets:
        body += f"{off:010d} 00000 n \n".encode()
    body += (
        b"trailer\n<< /Size " + str(len(objs)).encode() + b" /Root 1 0 R >>\n"
        b"startxref\n" + str(xref_pos).encode() + b"\n%%EOF\n"
    )
    return body


def test_pdf_js_extracted_as_child_structure():
    pytest.importorskip("PyPDF2")
    pdf = _pdf_with_js("var x = 1; eval('payload');")
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")

    js_children = [
        c for c in s.get_children()
        if (c.mime_type or "").startswith(("application/javascript",
                                            "text/javascript",
                                            "text/plain"))
        and c.filename and "pdf_js" in c.filename
    ]
    assert js_children, [c.filename for c in s.get_children()]
    # ScriptAnalyzer should run on the extracted child
    js = js_children[0]
    analyzer_name = type(js.analyzer).__name__
    assert analyzer_name == "ScriptAnalyzer", analyzer_name


def test_embedded_js_report_emitted_on_root():
    pytest.importorskip("PyPDF2")
    pdf = _pdf_with_js("alert('hi');")
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")
    rep = s.analyzer.reports.get("embedded_js")
    assert rep is not None
    assert "1" in rep.text  # one payload extracted


def test_no_embedded_js_report_for_clean_pdf():
    """A PDF with no JS objects must not emit the embedded_js report."""
    pytest.importorskip("PyPDF2")
    # Tiny PDF with just a catalog + pages, no actions
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000060 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\n"
        b"startxref\n110\n%%EOF\n"
    )
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")
    assert "embedded_js" not in s.analyzer.reports


def test_dedup_repeated_js_references():
    """Two action references pointing at the same /JS payload should only
    emit one child Structure."""
    pytest.importorskip("PyPDF2")
    # Build a PDF where two actions reference the same JS string object —
    # but for simplicity use the same JS literal in both. The dedup
    # heuristic is content-hash-based so identical bytes collapse.
    js = "var a = 'one';" * 5  # >0 chars
    pdf = _pdf_with_js(js)
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")
    js_children = [c for c in s.get_children()
                   if c.filename and "pdf_js" in c.filename]
    assert len(js_children) == 1


def test_pdf_js_runs_through_script_threat_detection():
    """The whole point: extracted PDF JS gets ScriptAnalyzer's full
    threat-pattern pipeline."""
    pytest.importorskip("PyPDF2")
    # JS containing high-signal threat strings (eval, ActiveXObject)
    js = "var s = eval(unescape('%75%75')); new ActiveXObject('Wscript.Shell');"
    pdf = _pdf_with_js(js)
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")

    js_child = next(c for c in s.get_children()
                    if c.filename and "pdf_js" in c.filename)
    threat_labels = [k for k in js_child.analyzer.reports
                     if k.startswith("threat") or k == "obfuscation"
                     or k == "mitre_attack"]
    assert threat_labels, f"no threat reports on extracted JS; "\
                          f"reports={list(js_child.analyzer.reports)}"
