"""Audit follow-up — Poppler PDF preview must not be a DoS surface.

Audit finding (codex_security_1: HIGH; codex_security_2: MEDIUM):
``PDFAnalyzer.generate_preview`` shelled out to pdftoppm via pdf2image
with no timeout, no DPI cap, no input-size gate, and no output-pixel
ceiling. A crafted PDF with pathological page geometry could pin
CPU/RAM. Preview is also a non-essential, opt-in-style feature, so
hard limits are appropriate.

These tests pin the corrected budget so future cleanup can't restore
the unbounded path.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker

PDFAnalyzer = pytest.importorskip("Analyzers.PDFAnalyzer").PDFAnalyzer


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _minimal_pdf() -> bytes:
    return (
        b"%PDF-1.7\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n"
        b"0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\nstartxref\n107\n%%EOF\n"
    )


# ---------------------------------------------------------------
# Budget constants are present and sane
# ---------------------------------------------------------------


def test_preview_budgets_defined():
    """All four budget constants must exist on the class — these are the
    knobs the security fix introduced. If a refactor renames or deletes
    them silently, the unbounded path is back."""
    assert isinstance(PDFAnalyzer._PREVIEW_TIMEOUT_S, int)
    assert isinstance(PDFAnalyzer._PREVIEW_DPI, int)
    assert isinstance(PDFAnalyzer._PREVIEW_MAX_INPUT_BYTES, int)
    assert isinstance(PDFAnalyzer._PREVIEW_MAX_PIXELS, int)
    # Sanity — not "unbounded" by accident
    assert PDFAnalyzer._PREVIEW_TIMEOUT_S <= 60
    assert PDFAnalyzer._PREVIEW_MAX_INPUT_BYTES <= 200 * 1024 * 1024
    assert PDFAnalyzer._PREVIEW_DPI <= 200
    assert PDFAnalyzer._PREVIEW_MAX_PIXELS <= 16_000_000


def test_oversize_input_skips_preview(monkeypatch):
    """A PDF larger than _PREVIEW_MAX_INPUT_BYTES must short-circuit the
    preview path before pdf2image is even imported."""
    pytest.importorskip("pypdf")

    # Force the budget tiny so we don't have to build a 50MB fixture
    monkeypatch.setattr(PDFAnalyzer, "_PREVIEW_MAX_INPUT_BYTES", 16)

    # Track whether convert_from_bytes is reached
    called = {"n": 0}
    fake_module = type("fake", (), {})()

    def fake_convert(*args, **kwargs):
        called["n"] += 1
        return []

    fake_module.convert_from_bytes = fake_convert
    import importlib
    real_import_module = importlib.import_module

    def fake_import_module(name):
        if name == "pdf2image":
            return fake_module
        return real_import_module(name)

    import sys
    pdfa = sys.modules["Analyzers.PDFAnalyzer"]
    monkeypatch.setattr(pdfa.importlib, "import_module", fake_import_module)

    pdf = _minimal_pdf()  # ~150 bytes; > 16-byte budget
    s = Structure.create(data=pdf, filename="t.pdf",
                         mime_type="application/pdf")
    # No preview report should land
    assert "preview" not in s.analyzer.reports
    # And convert_from_bytes was never called
    assert called["n"] == 0


def test_oversize_geometry_skips_preview_output(monkeypatch):
    """When pdf2image returns a page whose pixel area exceeds
    _PREVIEW_MAX_PIXELS, the preview report MUST NOT be emitted —
    even if everything else succeeded."""
    pytest.importorskip("pypdf")

    # Tiny pixel ceiling so we don't have to render a real big image
    monkeypatch.setattr(PDFAnalyzer, "_PREVIEW_MAX_PIXELS", 100)

    import importlib
    real_import_module = importlib.import_module

    class FakeImage:
        size = (1000, 1000)  # 1,000,000 pixels — far exceeds 100
        def save(self, buffer, format):
            buffer.write(b"\x89PNG\r\n\x1a\nfake")

    fake_module = type("fake", (), {})()
    fake_module.convert_from_bytes = lambda *a, **kw: [FakeImage()]

    def fake_import_module(name):
        if name == "pdf2image":
            return fake_module
        return real_import_module(name)

    import sys
    pdfa = sys.modules["Analyzers.PDFAnalyzer"]
    monkeypatch.setattr(pdfa.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(pdfa.shutil, "which", lambda _: "/usr/bin/pdftoppm")

    s = Structure.create(data=_minimal_pdf(), filename="t.pdf",
                         mime_type="application/pdf")
    assert "preview" not in s.analyzer.reports


def test_convert_from_bytes_called_with_dpi_and_timeout(monkeypatch):
    """The dpi and timeout kwargs must be threaded through to pdf2image
    so pdftoppm enforces them upstream of our budget checks."""
    pytest.importorskip("pypdf")

    captured = {}
    import importlib
    real_import_module = importlib.import_module

    class FakeImage:
        size = (50, 50)
        def save(self, buffer, format):
            buffer.write(b"\x89PNG\r\n\x1a\nfake")

    fake_module = type("fake", (), {})()

    def fake_convert(data, **kwargs):
        captured.update(kwargs)
        return [FakeImage()]

    fake_module.convert_from_bytes = fake_convert

    def fake_import_module(name):
        if name == "pdf2image":
            return fake_module
        return real_import_module(name)

    import sys
    pdfa = sys.modules["Analyzers.PDFAnalyzer"]
    monkeypatch.setattr(pdfa.importlib, "import_module", fake_import_module)
    monkeypatch.setattr(pdfa.shutil, "which", lambda _: "/usr/bin/pdftoppm")

    Structure.create(data=_minimal_pdf(), filename="t.pdf",
                     mime_type="application/pdf")
    assert "dpi" in captured
    assert captured["dpi"] == PDFAnalyzer._PREVIEW_DPI
    assert "timeout" in captured
    assert captured["timeout"] == PDFAnalyzer._PREVIEW_TIMEOUT_S
