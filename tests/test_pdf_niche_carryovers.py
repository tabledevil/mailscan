"""Niche PDF detection items carried over from the audit triage at
the user's request.

#37 PDF-specific shellcode-string heap-spray fingerprints
    (0c0c0c0c IE/Adobe family, AAAA / 41414141 fill, NSCK/NSCM markers)
#38 Adobe-specific embedded Flash detection
    (legacy /Subtype /Flash3D annotation; ``application/x-shockwave-
    flash`` MIME marker; raw SWF magic ``CWS``/``FWS``/``ZWS``)
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Severity
from Utils import pdf_policy
from Utils.js_analysis import detect_threat_patterns


def _names(findings):
    return {f["pattern"] for f in findings}


# ---------------------------------------------------------------
# #37 Heap-spray fingerprints
# ---------------------------------------------------------------


def test_0c0c0c0c_spray_fingerprint_detected():
    """The IE/Adobe-family heap-spray fill from published exploit PoCs."""
    src = "var sled = '" + "0c0c0c0c" * 10 + "';"
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_0c0c" in found


def test_0c0c0c0c_unicode_form_detected():
    src = "var sled = unescape('" + "%u0c0c" * 12 + "');"
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_0c0c" in found


def test_aaaa_long_run_detected():
    src = "var fill = '" + "41414141" * 10 + "';"
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_aaaa" in found


def test_aaaa_url_encoded_detected():
    src = "var x = unescape('" + "%41" * 35 + "');"
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_aaaa" in found


def test_metasploit_marker_nsck_detected():
    src = "var s = unescape('%uNSCK%uNSCK');"
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_marker" in found


def test_metasploit_marker_nscm_detected():
    src = "var s = unescape('%uNSCM');"
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_marker" in found


def test_short_runs_do_not_fire():
    """Short literal occurrences must not fire — the threshold guards
    against incidental hex strings in legit code."""
    src = "var x = '0c0c0c0c';"  # only 1 occurrence
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_0c0c" not in found


def test_normal_constants_do_not_fire():
    """Generic JS that uses 'AAAA' as a placeholder string in a test
    must not light up — needs 8+ runs to qualify."""
    src = 'var greeting = "AAAA";'
    found = _names(detect_threat_patterns(src))
    assert "pdf_heap_spray_aaaa" not in found


# ---------------------------------------------------------------
# #38 Embedded Flash detection
# ---------------------------------------------------------------


def test_flash3d_annotation_subtype_detected():
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Annot /Subtype /Flash3D >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.kind == "annotation" and f.name == "Flash3D"
               for f in findings)


def test_flash3d_blocked_under_standard():
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Annot /Subtype /Flash3D >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    verdicts = pdf_policy.evaluate(findings, "standard")
    assert any(v.finding.name == "Flash3D" for v in verdicts)


def test_shockwave_flash_mime_detected():
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Filespec /F (movie.swf) /Subtype "
        b"(application/x-shockwave-flash) >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.name == "EmbeddedFlash" for f in findings)


def test_swf_magic_in_stream_detected():
    """Even when the MIME marker is absent, the raw SWF magic at the
    start of an embedded blob betrays Flash content."""
    pdf = (
        b"%PDF-1.7\n"
        b"5 0 obj << /Length 20 >> stream\n"
        b"CWS\x0c \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\nendstream endobj\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert any(f.name == "EmbeddedFlash" for f in findings)


def test_clean_pdf_no_flash_finding():
    """Plain PDF without any Flash carrier must not light up."""
    pdf = (
        b"%PDF-1.7\n"
        b"<< /Type /Catalog /Pages 2 0 R >>\n"
        b"%%EOF\n"
    )
    findings = pdf_policy.scan(pdf)
    assert not any(f.name == "EmbeddedFlash" for f in findings)
