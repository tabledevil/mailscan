"""Sprint 8 — extract inline images + embedded fonts from PDFs as
resource children. Inline images flow into QRAnalyzer; fonts surface
shellcode-bearing font streams from older exploit chains."""

import io
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


def _assemble_pdf(objs: list[bytes], root_id: int = 1) -> bytes:
    body = b"%PDF-1.7\n"
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


def _pdf_with_jpeg_xobject() -> bytes:
    # Minimal JPEG SOI..EOI marker pair (decodable shape, not actual image)
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00" \
           + b"\x00" * 100 + b"\xff\xd9"
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
        b"/Resources << /XObject << /Im0 4 0 R >> >> >>"
    )
    objs.append(
        b"<< /Type /XObject /Subtype /Image /Width 10 /Height 10 "
        b"/BitsPerComponent 8 /ColorSpace /DeviceRGB /Filter /DCTDecode "
        b"/Length " + str(len(jpeg)).encode() + b" >>\nstream\n"
        + jpeg + b"\nendstream"
    )
    return _assemble_pdf(objs)


def _pdf_with_embedded_font() -> bytes:
    font_bytes = b"\x00\x01\x00\x00" + b"OS/2" + b"X" * 200  # TTF-shaped sentinel
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objs.append(
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
        b"/Resources << /Font << /F1 4 0 R >> >> >>"
    )
    # Font dict pointing at FontDescriptor with /FontFile2
    objs.append(
        b"<< /Type /Font /Subtype /TrueType /BaseFont /MyFont "
        b"/FontDescriptor 5 0 R >>"
    )
    objs.append(
        b"<< /Type /FontDescriptor /FontName /MyFont /FontFile2 6 0 R >>"
    )
    objs.append(
        b"<< /Length " + str(len(font_bytes)).encode()
        + b" >>\nstream\n" + font_bytes + b"\nendstream"
    )
    return _assemble_pdf(objs)


# ---------------------------------------------------------------
# Tests
# ---------------------------------------------------------------


def test_inline_jpeg_image_extracted():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_pdf_with_jpeg_xobject(),
                         filename="img.pdf",
                         mime_type="application/pdf")
    images = [c for c in s.get_children()
              if c.filename and "_image_" in c.filename]
    assert images, [c.filename for c in s.get_children()]
    img = images[0]
    assert img.filename.endswith(".jpg")
    # Stream payload preserved as JPEG SOI..EOI
    assert img.rawdata.startswith(b"\xff\xd8\xff")


def test_embedded_font_extracted():
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_pdf_with_embedded_font(),
                         filename="font.pdf",
                         mime_type="application/pdf")
    fonts = [c for c in s.get_children()
             if c.filename and "_font_" in c.filename]
    assert fonts, [c.filename for c in s.get_children()]
    f = fonts[0]
    assert f.filename.endswith(".ttf")
    assert b"OS/2" in f.rawdata


def test_no_report_clutter_for_resource_extraction():
    """Pulling fonts and images on every PDF would fire reports on
    every legitimate document. Resource extraction must be silent —
    only what downstream analyzers find on the resource bytes shows."""
    pytest.importorskip("PyPDF2")
    s = Structure.create(data=_pdf_with_jpeg_xobject(),
                         filename="img.pdf",
                         mime_type="application/pdf")
    # No "resources" / "inline_image" / "extracted_image" report on root
    for label in s.analyzer.reports:
        assert "resource" not in label.lower()
        assert "inline_image" not in label.lower()
        assert "extracted_image" not in label.lower()


def test_dedup_repeated_xobject():
    """Two pages referencing the same image XObject should only emit
    one child Structure (content-hash dedup)."""
    pytest.importorskip("PyPDF2")
    jpeg = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + b"X" * 50 + b"\xff\xd9"
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>")
    # both pages reference the same XObject 5 0 R
    for page_id in (3, 4):
        objs.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] "
            b"/Resources << /XObject << /Im0 5 0 R >> >> >>"
        )
    objs.append(
        b"<< /Type /XObject /Subtype /Image /Width 10 /Height 10 "
        b"/BitsPerComponent 8 /ColorSpace /DeviceRGB /Filter /DCTDecode "
        b"/Length " + str(len(jpeg)).encode() + b" >>\nstream\n"
        + jpeg + b"\nendstream"
    )
    s = Structure.create(data=_assemble_pdf(objs), filename="dup.pdf",
                         mime_type="application/pdf")
    imgs = [c for c in s.get_children()
            if c.filename and "_image_" in c.filename]
    assert len(imgs) == 1, [c.filename for c in imgs]
