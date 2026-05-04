"""Sprint 8 — complete PDF embedded-file harvesting + incremental-update awareness.

Covers portfolio-style PDFs (hierarchical name trees), FileAttachment
annotations, /AF Associated Files, and incremental updates with
multi-version objects.
"""

import os
import sys
import zlib

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


# ---------------------------------------------------------------
# PDF builders
# ---------------------------------------------------------------


def _assemble_pdf(objs: list[bytes], root_id: int = 1, header: bytes = b"%PDF-1.7\n") -> bytes:
    """Assemble a list of object bodies (1-indexed; objs[0] ignored)
    into a complete PDF with xref + trailer."""
    body = header
    offsets = []
    for i in range(1, len(objs)):
        offsets.append(len(body))
        body += f"{i} 0 obj\n".encode() + objs[i] + b"\nendobj\n"
    xref_pos = len(body)
    body += b"xref\n0 " + str(len(objs)).encode() + b"\n0000000000 65535 f \n"
    for off in offsets:
        body += f"{off:010d} 00000 n \n".encode()
    body += (b"trailer << /Size " + str(len(objs)).encode()
             + f" /Root {root_id} 0 R >>\nstartxref\n".encode()
             + str(xref_pos).encode() + b"\n%%EOF\n")
    return body


def _portfolio_pdf() -> bytes:
    """Build a portfolio-style PDF with 4 embedded files via a hierarchical
    /Kids name tree. Each leaf has its own /Names array."""
    payloads = {
        b"inner.pdf":   b"%PDF-1.4\n%inner-pdf-bytes\n%%EOF",
        b"report.docx": b"PK\x03\x04docx-zip-bytes-and-some-content",
        b"font.ttf":    b"\x00\x01\x00\x00ttf-bytes",
        b"image.png":   b"\x89PNG\r\n\x1a\nimage-bytes",
    }
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R /Names 3 0 R "
                b"/Collection 4 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objs.append(b"<< /EmbeddedFiles 5 0 R >>")
    objs.append(b"<< /Type /Collection /View /T >>")
    objs.append(b"<< /Kids [6 0 R 7 0 R] >>")
    # Reserve slots 6, 7
    objs.append(b"<<placeholder6>>")
    objs.append(b"<<placeholder7>>")

    next_id = 8
    leaves = [(6, [b"font.ttf", b"image.png"]),
              (7, [b"inner.pdf", b"report.docx"])]
    for leaf_id, names in leaves:
        pairs = []
        for name in names:
            pairs.append(b"(" + name + b")")
            pairs.append(f"{next_id} 0 R".encode())
            objs.append(
                b"<< /Type /Filespec /F (" + name + b") /EF << /F "
                + f"{next_id+1} 0 R".encode() + b" >> >>"
            )
            data = payloads[name]
            objs.append(b"<< /Length " + str(len(data)).encode()
                        + b" >>\nstream\n" + data + b"\nendstream")
            next_id += 2
        objs[leaf_id] = (
            b"<< /Names [" + b" ".join(pairs) + b"] /Limits [("
            + names[0] + b") (" + names[-1] + b")] >>"
        )
    return _assemble_pdf(objs, root_id=1)


def _af_pdf() -> bytes:
    """PDF with one /AF (Associated File) — common in PDF/A-3 invoices
    that carry the structured XML alongside the rendered PDF."""
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R /AF [3 0 R] >>")
    objs.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objs.append(b"<< /Type /Filespec /F (factur-x.xml) /EF << /F 4 0 R >> >>")
    xml = b"<?xml version='1.0'?><invoice><amount>42</amount></invoice>"
    objs.append(b"<< /Length " + str(len(xml)).encode()
                + b" >>\nstream\n" + xml + b"\nendstream")
    return _assemble_pdf(objs, root_id=1)


def _file_attachment_annot_pdf() -> bytes:
    """PDF with a /Subtype /FileAttachment annotation on its single page."""
    payload = b"secret-attachment-content"
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(b"<< /Type /Page /Parent 2 0 R /Annots [4 0 R] "
                b"/MediaBox [0 0 100 100] >>")
    objs.append(b"<< /Type /Annot /Subtype /FileAttachment /FS 5 0 R >>")
    objs.append(b"<< /Type /Filespec /F (attached.bin) /EF << /F 6 0 R >> >>")
    objs.append(b"<< /Length " + str(len(payload)).encode()
                + b" >>\nstream\n" + payload + b"\nendstream")
    return _assemble_pdf(objs, root_id=1)


def _incremental_update_pdf() -> bytes:
    """Original PDF + an appended block (post-%%EOF) that redefines the
    catalog and adds an /OpenAction → /JavaScript action.

    The structure is intentionally not parser-pristine; the goal is to
    exercise the byte-level incremental-update detector."""
    orig = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\nstartxref\n107\n%%EOF\n"
    )
    incr = (
        b"3 0 obj << /Type /Action /S /JavaScript /JS (eval('attack');) >> endobj\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >> endobj\n"
    )
    xref2_off = len(orig) + len(incr)
    incr += (
        b"xref\n0 1\n0000000000 65535 f \n"
        b"trailer << /Size 4 /Root 1 0 R /Prev 107 >>\nstartxref\n"
        + str(xref2_off).encode() + b"\n%%EOF\n"
    )
    return orig + incr


# ---------------------------------------------------------------
# Tests
# ---------------------------------------------------------------


def test_portfolio_pdf_extracts_all_embedded_files():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_portfolio_pdf(), filename="portfolio.pdf",
                         mime_type="application/pdf")
    children = [c for c in s.get_children() if c.filename and "." in c.filename]
    names = sorted(c.filename for c in children)
    # All four embedded files should be present in any order
    assert "inner.pdf" in names
    assert "report.docx" in names
    assert "font.ttf" in names
    assert "image.png" in names
    # And the embedded_files report fired
    rep = s.analyzer.reports.get("embedded_files")
    assert rep is not None
    assert rep.data["count"] == 4

    # Audit finding #20 (gemini_test_cov_2; HIGH): asserting on filename
    # presence alone misses regressions where the parser extracts
    # zero-byte or truncated children. Validate the actual bytes for
    # each known payload.
    by_name = {c.filename: c for c in children}
    expected = {
        b"inner.pdf":   b"%PDF-1.4\n%inner-pdf-bytes\n%%EOF",
        b"report.docx": b"PK\x03\x04docx-zip-bytes-and-some-content",
        b"font.ttf":    b"\x00\x01\x00\x00ttf-bytes",
        b"image.png":   b"\x89PNG\r\n\x1a\nimage-bytes",
    }
    for name_bytes, want in expected.items():
        name = name_bytes.decode()
        assert name in by_name
        assert by_name[name].rawdata == want, (
            f"{name}: got {by_name[name].rawdata!r}"
        )


def test_af_associated_files_extracted():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_af_pdf(), filename="invoice.pdf",
                         mime_type="application/pdf")
    children_by_name = {c.filename: c for c in s.get_children()
                        if c.filename}
    assert "factur-x.xml" in children_by_name
    # Audit #20: verify content bytes, not just filename presence
    expected = b"<?xml version='1.0'?><invoice><amount>42</amount></invoice>"
    assert children_by_name["factur-x.xml"].rawdata == expected
    rep = s.analyzer.reports.get("embedded_files")
    assert rep is not None
    assert "AF" in rep.data["by_source"]


def test_file_attachment_annotation_extracted():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_file_attachment_annot_pdf(),
                         filename="annot.pdf",
                         mime_type="application/pdf")
    children_by_name = {c.filename: c for c in s.get_children()
                        if c.filename}
    assert "attached.bin" in children_by_name
    # Audit #20: verify content bytes
    assert children_by_name["attached.bin"].rawdata == b"secret-attachment-content"
    rep = s.analyzer.reports.get("embedded_files")
    assert rep is not None
    assert "fileattachment_annot" in rep.data["by_source"]


def test_incremental_update_detected():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_incremental_update_pdf(),
                         filename="incr.pdf",
                         mime_type="application/pdf")
    rep = s.analyzer.reports.get("incremental_updates")
    assert rep is not None
    assert rep.data["updates"] == 1
    # The appended region adds /JavaScript and /OpenAction — must escalate
    from structure import Severity
    assert rep.severity == Severity.HIGH


def test_benign_incremental_update_is_info():
    """An update that only appends static content (no active surfaces)
    should report INFO, not HIGH — signed PDFs and editor-resaves do
    this routinely."""
    pytest.importorskip("PyPDF2")
    benign = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\nstartxref\n107\n%%EOF\n"
        # appended: just a plain dict, no active content
        b"3 0 obj << /Title (added later) >> endobj\n"
        b"xref\n0 1\n0000000000 65535 f \n"
        b"trailer << /Size 4 /Root 1 0 R /Prev 107 >>\nstartxref\n200\n%%EOF\n"
    )
    s = Structure.create(data=benign, filename="benign.pdf",
                         mime_type="application/pdf")
    rep = s.analyzer.reports.get("incremental_updates")
    assert rep is not None
    from structure import Severity
    assert rep.severity == Severity.INFO


def test_redefined_object_emitted_as_forensic_child():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_incremental_update_pdf(),
                         filename="incr.pdf",
                         mime_type="application/pdf")
    rep = s.analyzer.reports.get("redefined_objects")
    assert rep is not None
    assert any(o["id"] == 1 for o in rep.data["objects"])
    # The earlier version of object 1 should be exposed as a child
    historical = [c for c in s.get_children()
                  if c.filename and c.filename.startswith("pdf_obj_1_")]
    assert historical, [c.filename for c in s.get_children()]


def test_no_incremental_report_for_single_eof_pdf():
    pytest.importorskip("PyPDF2")
    pdf = (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\nstartxref\n107\n%%EOF\n"
    )
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")
    assert "incremental_updates" not in s.analyzer.reports
    assert "redefined_objects" not in s.analyzer.reports


def test_dedup_attachments_names_tree_vs_af():
    """Names-tree and /AF both pointing at the same Filespec should
    dedup. (Renamed from the original ``test_dedup_attachments_by_content_hash``
    which claimed to test FileAttachment annotations but actually only
    used Names + /AF — see ``test_dedup_attachments_names_tree_vs_fileattachment_annot``
    below for the genuine annotation-vs-tree dedup case.)"""
    pytest.importorskip("PyPDF2")
    payload = b"shared-attachment-bytes"
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R /Names 3 0 R /AF [4 0 R] >>")
    objs.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objs.append(b"<< /EmbeddedFiles << /Names "
                b"[(shared.bin) 4 0 R] >> >>")
    objs.append(b"<< /Type /Filespec /F (shared.bin) /EF << /F 5 0 R >> >>")
    objs.append(b"<< /Length " + str(len(payload)).encode()
                + b" >>\nstream\n" + payload + b"\nendstream")
    s = Structure.create(data=_assemble_pdf(objs, root_id=1),
                         filename="dup.pdf", mime_type="application/pdf")
    # Same payload referenced twice — should appear once
    matches = [c for c in s.get_children() if c.filename == "shared.bin"]
    assert len(matches) == 1


def test_dedup_attachments_names_tree_vs_fileattachment_annot():
    """Audit finding #19 (codex_test_cov_1, codex_test_cov_2; HIGH):
    the original ``test_dedup_attachments_by_content_hash`` claimed to
    cover the names-tree vs FileAttachment-annotation dedup branch but
    its fixture only used Names + /AF. The annotation branch
    (``Analyzers/PDFAnalyzer.py:317-322``) had zero direct coverage.

    This test builds a PDF where the SAME payload is reachable both
    via ``/Names/EmbeddedFiles`` and via a ``/Subtype /FileAttachment``
    annotation, and verifies the cross-source dedup actually fires."""
    pytest.importorskip("PyPDF2")
    payload = b"shared-via-tree-and-annot"
    objs: list[bytes] = [b""]
    # 1: catalog with Names tree pointing at the shared filespec
    objs.append(b"<< /Type /Catalog /Pages 2 0 R /Names 3 0 R >>")
    # 2: pages with a single page that has a FileAttachment annot
    objs.append(b"<< /Type /Pages /Kids [4 0 R] /Count 1 >>")
    # 3: names dict pointing at the same filespec
    objs.append(b"<< /EmbeddedFiles << /Names "
                b"[(shared.bin) 5 0 R] >> >>")
    # 4: page with the FileAttachment annot
    objs.append(b"<< /Type /Page /Parent 2 0 R /Annots [6 0 R] "
                b"/MediaBox [0 0 100 100] >>")
    # 5: shared filespec — both paths reach this
    objs.append(b"<< /Type /Filespec /F (shared.bin) /EF << /F 7 0 R >> >>")
    # 6: FileAttachment annot pointing at the same filespec (object 5)
    objs.append(b"<< /Type /Annot /Subtype /FileAttachment /FS 5 0 R >>")
    # 7: stream with the actual bytes
    objs.append(b"<< /Length " + str(len(payload)).encode()
                + b" >>\nstream\n" + payload + b"\nendstream")
    s = Structure.create(data=_assemble_pdf(objs, root_id=1),
                         filename="dup-cross.pdf",
                         mime_type="application/pdf")
    matches = [c for c in s.get_children() if c.filename == "shared.bin"]
    assert len(matches) == 1, [c.filename for c in matches]
    assert matches[0].rawdata == payload
