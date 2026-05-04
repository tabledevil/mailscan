"""Audit follow-up — PDF policy correctness gaps from the audit fleet.

Pins fixes for:
  #6  literal-string false positives  — _strip_pdf_string_literals
  #7  indirect-reference invisibility — /Foo 5 0 R structural matchers
  #8  filter-array only first match   — _RE_FILTER_ARRAY iteration
  #2  /ObjStm decompression budget    — _bounded_decompress + total cap
"""

import os
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils import pdf_policy


# ---------------------------------------------------------------
# #6 literal strings
# ---------------------------------------------------------------


def test_marker_inside_literal_string_does_not_fire():
    """Marker tokens like /S /Launch inside a PDF string literal — say,
    a metadata title — must not produce findings."""
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Title (/S /Launch slide deck) /Type /Catalog /Pages 2 0 R >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert not any(f.kind == "action" and f.name == "Launch"
                   for f in findings)


def test_marker_inside_nested_balanced_parens():
    """Balanced nested parens are legal in PDF strings; the scanner must
    swallow them all rather than terminating early."""
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Title (outer (inner /S /Launch) tail) >>\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert not any(f.kind == "action" and f.name == "Launch"
                   for f in findings)


def test_marker_inside_string_with_escaped_paren():
    """Escaped parens inside literals must NOT toggle nesting depth."""
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Title (text \\(escaped open then /S /Launch) more) >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert not any(f.kind == "action" and f.name == "Launch"
                   for f in findings)


def test_real_action_outside_literal_still_fires():
    """Sanity — the literal-string strip must not break real findings."""
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Catalog /OpenAction << /S /Launch /F (calc.exe) >> >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "action" and f.name == "Launch"
               for f in findings)


def test_stream_body_does_not_corrupt_literal_string_strip():
    """Discovered while wiring up the literal-string strip: compressed
    stream bodies contain random ``(`` bytes which are NOT PDF string
    literals. Without ``_strip_pdf_stream_bodies`` first, the literal-
    string pass would chew across stream content and consume real
    markers in the appended /ObjStm decoded payload.

    Regression guard: the simplest possible failure shape — a stream
    body with binary parens followed by a real /ObjStm action."""
    import zlib
    inner = b"5 0 obj << /Type /Action /S /JavaScript /JS (alert('x')) >> endobj"
    compressed = zlib.compress(inner)
    objstm = (
        b"<< /Type /ObjStm /N 1 /First 0 /Filter /FlateDecode /Length "
        + str(len(compressed)).encode() + b" >>\n"
        b"stream\n" + compressed + b"\nendstream"
    )
    pdf = b"%PDF-1.7\n" + objstm + b"\n%%EOF\n"
    findings = pdf_policy.scan(pdf)
    # The decoded inner contains /S /JavaScript and is appended after
    # decompression — must still be detected.
    assert any(f.kind == "action" and "JavaScript" in f.name
               for f in findings), [(f.kind, f.name) for f in findings]


# ---------------------------------------------------------------
# #7 indirect references
# ---------------------------------------------------------------


def test_acroform_indirect_reference_detected():
    """/AcroForm 5 0 R (the common real-world shape) must be detected,
    not just /AcroForm <<...>>."""
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Catalog /AcroForm 5 0 R /Pages 2 0 R >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "structural" and f.name == "AcroForm"
               for f in findings), [(f.kind, f.name) for f in findings]


def test_aa_indirect_reference_detected():
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Catalog /AA 7 0 R /Pages 2 0 R >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "structural" and f.name == "AdditionalActions"
               for f in findings)


def test_javascript_nametree_indirect_reference_detected():
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Names << /JavaScript 9 0 R >> /Type /Catalog /Pages 2 0 R >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "structural"
               and "JavaScript" in f.name
               for f in findings)


# ---------------------------------------------------------------
# #8 filter array — every filter, not just first
# ---------------------------------------------------------------


def test_filter_array_detects_secondary_jbig2():
    """``/Filter [/FlateDecode /JBIG2Decode]`` must yield BOTH filters,
    not silently skip the dangerous secondary."""
    pdf = (
        b"%PDF-1.7\n"
        b"5 0 obj << /Length 100 /Filter [/FlateDecode /JBIG2Decode] >> "
        b"stream\nstubstubstubstub\nendstream endobj\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    filters = {f.name for f in findings if f.kind == "filter"}
    assert "FlateDecode" in filters
    assert "JBIG2Decode" in filters


def test_filter_array_three_filters_all_detected():
    pdf = (
        b"%PDF-1.7\n"
        b"5 0 obj << /Filter [/ASCIIHexDecode /LZWDecode /CCITTFaxDecode] "
        b"/Length 50 >> stream\nstub\nendstream endobj\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    filters = {f.name for f in findings if f.kind == "filter"}
    assert "ASCIIHexDecode" in filters
    assert "LZWDecode" in filters
    assert "CCITTFaxDecode" in filters


def test_single_filter_form_still_works():
    pdf = (
        b"%PDF-1.7\n"
        b"5 0 obj << /Length 10 /Filter /JBIG2Decode >> "
        b"stream\nstubstubst\nendstream endobj\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "filter" and f.name == "JBIG2Decode"
               for f in findings)


# ---------------------------------------------------------------
# #2 ObjStm decompression budget
# ---------------------------------------------------------------


def test_bounded_decompress_caps_at_max_bytes():
    """A bomb-shaped stream (highly compressible) must be rejected
    when decompressed size exceeds the budget."""
    bomb = zlib.compress(b"A" * 10_000_000)  # 10 MB decoded
    result = pdf_policy._bounded_decompress(bomb, max_bytes=1024)
    assert result is None


def test_bounded_decompress_normal_stream_returns_bytes():
    payload = b"<< /Type /Action /S /Launch >>"
    compressed = zlib.compress(payload)
    result = pdf_policy._bounded_decompress(
        compressed, max_bytes=10 * 1024 * 1024,
    )
    assert result == payload


def test_objstm_total_budget_truncates_after_first_oversize_stream():
    """Cumulative decoded payload across multiple ObjStm must respect
    _OBJSTM_MAX_TOTAL_BYTES — once exceeded, scan continues but
    further streams are skipped (graceful degradation, not crash)."""
    # Build a PDF with two ObjStm streams. First decodes within budget,
    # second alone fits but pushes total over budget.
    half = b"X" * (pdf_policy._OBJSTM_MAX_TOTAL_BYTES // 2 + 1)
    compressed_half = zlib.compress(half)

    def _objstm_obj(idnum: int, compressed: bytes) -> bytes:
        return (b"%d 0 obj\n<< /Type /ObjStm /N 1 /First 0 "
                b"/Filter /FlateDecode /Length %d >>\n"
                b"stream\n%s\nendstream\nendobj\n"
                % (idnum, len(compressed), compressed))

    pdf = (b"%PDF-1.7\n"
           + _objstm_obj(5, compressed_half)
           + _objstm_obj(6, compressed_half)
           + b"%%EOF\n")
    decoded = pdf_policy._decompress_objstms(pdf)
    # First stream's payload is present; second was over the cumulative
    # budget so it's dropped. Length must be bounded.
    assert len(decoded) <= pdf_policy._OBJSTM_MAX_TOTAL_BYTES + 64


def test_objstm_per_stream_bomb_skipped():
    """An individual /ObjStm whose decoded size exceeds
    _OBJSTM_MAX_PER_STREAM_BYTES must be silently skipped (not crash
    the scan, not consume RAM)."""
    bomb = zlib.compress(b"\x00" * (pdf_policy._OBJSTM_MAX_PER_STREAM_BYTES + 100))
    pdf = (
        b"%PDF-1.7\n"
        b"5 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /Length "
        + str(len(bomb)).encode() + b" >>\nstream\n" + bomb
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    # Must not raise, and must not return the bomb's bytes
    decoded = pdf_policy._decompress_objstms(pdf)
    assert b"\x00" * 1024 not in decoded
