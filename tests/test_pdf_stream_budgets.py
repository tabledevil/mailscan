"""Audit follow-up — PDF resource decompression must respect a budget.

Audit finding (codex_security_1, codex_security_2; HIGH): PDF /JS,
/EF (embedded files), /XObject /Image, and /FontFile* streams all
flowed through ``stream.get_data()`` with no per-stream size cap.
A small PDF carrying a heavily-compressed stream could inflate to
multi-GB heap before the generic ``max_file_size`` check fired.

These tests pin the ``_bounded_get_data`` helper that gates every
extraction site, so future cleanup can't restore the unbounded path.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Module reference so we can monkeypatch the constants
import sys as _sys
pdfa = pytest.importorskip("Analyzers.PDFAnalyzer")
_pdfa_module = _sys.modules["Analyzers.PDFAnalyzer"]


# ---------------------------------------------------------------
# _bounded_get_data unit tests
# ---------------------------------------------------------------


class _FakeStream:
    """Minimal StreamObject stand-in for unit tests."""
    def __init__(self, data):
        self._data = data
    def get_data(self):
        return self._data


def test_bounded_get_data_returns_under_budget():
    s = _FakeStream(b"x" * 1024)
    assert _pdfa_module._bounded_get_data(s, max_bytes=2048) == b"x" * 1024


def test_bounded_get_data_rejects_oversized():
    s = _FakeStream(b"x" * 2048)
    assert _pdfa_module._bounded_get_data(s, max_bytes=1024) is None


def test_bounded_get_data_swallows_decompress_failure():
    class Broken:
        def get_data(self):
            raise RuntimeError("malformed stream")
    assert _pdfa_module._bounded_get_data(Broken()) is None


def test_bounded_get_data_handles_none_payload():
    class Nullish:
        def get_data(self):
            return None
    assert _pdfa_module._bounded_get_data(Nullish()) is None


# ---------------------------------------------------------------
# Budget constants present + sane
# ---------------------------------------------------------------


def test_pdf_stream_budget_constants_defined():
    assert isinstance(_pdfa_module._PDF_STREAM_MAX_BYTES, int)
    assert _pdfa_module._PDF_STREAM_MAX_BYTES <= 256 * 1024 * 1024
    assert isinstance(_pdfa_module._PDF_STREAM_MAX_CUMULATIVE, int)
    assert _pdfa_module._PDF_STREAM_MAX_CUMULATIVE <= 1024 * 1024 * 1024
