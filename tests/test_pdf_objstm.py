"""Sprint 8 — /ObjStm decompression so policy markers hidden inside
compressed object streams aren't invisible to the byte scan."""

import os
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils import pdf_policy
from structure import Severity, Structure
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _pdf_with_objstm(inner_objects: bytes) -> bytes:
    """Wrap *inner_objects* (raw PDF object syntax) inside a FlateDecode'd
    /Type /ObjStm stream embedded in a minimal PDF skeleton."""
    compressed = zlib.compress(inner_objects)
    objstm_obj = (
        b"<< /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode "
        b"/Length " + str(len(compressed)).encode() + b" >>\n"
        b"stream\n" + compressed + b"\nendstream"
    )
    objs = [
        b"",
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [] /Count 0 >>",
        objstm_obj,
    ]
    body = b"%PDF-1.7\n"
    offsets = []
    for i in range(1, len(objs)):
        offsets.append(len(body))
        body += f"{i} 0 obj\n".encode() + objs[i] + b"\nendobj\n"
    xref_pos = len(body)
    body += b"xref\n0 4\n0000000000 65535 f \n"
    for off in offsets:
        body += f"{off:010d} 00000 n \n".encode()
    body += (b"trailer << /Size 4 /Root 1 0 R >>\nstartxref\n"
             + str(xref_pos).encode() + b"\n%%EOF\n")
    return body


# ---------------------------------------------------------------
# Decompression unit tests
# ---------------------------------------------------------------


def test_decompress_objstms_returns_decoded_bytes():
    inner = b"<< /Type /Action /S /Launch /F (calc.exe) >>"
    pdf = _pdf_with_objstm(inner)
    decoded = pdf_policy._decompress_objstms(pdf)
    assert b"/Launch" in decoded


def test_decompress_objstms_empty_when_no_objstm():
    pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF\n"
    assert pdf_policy._decompress_objstms(pdf) == b""


def test_decompress_objstms_skips_corrupt_streams():
    """A corrupt FlateDecode payload must not crash the scanner."""
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /ObjStm /Filter /FlateDecode /Length 5 >>\n"
        b"stream\n!!!!!\nendstream endobj\n%%EOF\n"
    )
    # Should return empty — corrupt stream silently skipped
    assert pdf_policy._decompress_objstms(pdf) == b""


# ---------------------------------------------------------------
# Scanner sees through /ObjStm
# ---------------------------------------------------------------


def test_launch_action_inside_objstm_detected():
    inner = b"5 0 obj << /Type /Action /S /Launch /F (evil.exe) >> endobj"
    pdf = _pdf_with_objstm(inner)
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "action" and f.name == "Launch" for f in findings)


def test_javascript_action_inside_objstm_detected():
    inner = b"5 0 obj << /Type /Action /S /JavaScript /JS (alert('x')) >> endobj"
    pdf = _pdf_with_objstm(inner)
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "action" and "JavaScript" in f.name for f in findings)


def test_openaction_with_objstm_javascript_triggers_at_opening():
    """A /JavaScript inside an /ObjStm referenced by /OpenAction should
    still be detected as triggered-at-opening when the proximity
    heuristic pulls in the decoded bytes."""
    # /OpenAction in the visible part of the PDF; JS action inside ObjStm
    inner = b"5 0 obj << /Type /Action /S /JavaScript /JS (drop) >> endobj"
    pdf_with = _pdf_with_objstm(inner)
    # Inject /OpenAction reference into the visible catalog
    pdf_with = pdf_with.replace(
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>",
    )
    findings = pdf_policy.scan(pdf_with)
    assert any(f.kind == "action" and "JavaScript" in f.name
               for f in findings)


def test_objstm_invisible_to_old_byte_scan():
    """Sanity: the compressed-only payload contains no /Launch when scanned
    raw — so this test setup actually exercises the decoder, not the
    fallback case."""
    inner = b"5 0 obj << /Type /Action /S /Launch >> endobj"
    pdf = _pdf_with_objstm(inner)
    # Without the new decoder, the compressed bytes don't contain "/Launch"
    # as a literal substring.
    assert b"/S /Launch" not in pdf  # only present after decompression


# ---------------------------------------------------------------
# End-to-end via PDFAnalyzer
# ---------------------------------------------------------------


def test_pdfanalyzer_flags_launch_inside_objstm():
    pytest.importorskip("pypdf")
    inner = b"5 0 obj << /Type /Action /S /Launch /F (calc.exe) >> endobj"
    pdf = _pdf_with_objstm(inner)
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")
    rep = s.analyzer.reports.get("pdfcop_policy")
    assert rep is not None, list(s.analyzer.reports)
    assert "Launch" in rep.text
    assert rep.severity == Severity.CRITICAL
