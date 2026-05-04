"""Sprint 8 — pdfcop policy parity (native port)."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils import pdf_policy
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# ---------------------------------------------------------------
# Hand-crafted PDF byte fragments — minimal but valid enough for our
# regex-based scanner to dispatch on. Real PDFs are objects + offsets,
# but pdfcop's coverage is reproduced via marker scanning on the bytes.
# ---------------------------------------------------------------


def _pdf_with(body: bytes) -> bytes:
    """Wrap body fragments in a minimal PDF skeleton so the scan accepts
    the file via the %PDF- magic check."""
    return b"%PDF-1.7\n" + body + b"\n%%EOF\n"


# ---------------------------------------------------------------
# 1. Profile structure — verbatim translation parity check
# ---------------------------------------------------------------


def test_all_four_profiles_present():
    assert set(pdf_policy.PROFILES) == {"standard", "strong", "paranoid", "none"}


def test_standard_profile_blocks_launch_action():
    assert pdf_policy.PROFILES["standard"]["allowLaunchAction"] is False


def test_paranoid_blocks_uri_but_standard_allows():
    assert pdf_policy.PROFILES["standard"]["allowURIAction"] is True
    assert pdf_policy.PROFILES["paranoid"]["allowURIAction"] is False


def test_strong_blocks_js_but_standard_allows():
    assert pdf_policy.PROFILES["standard"]["allowJS"] is True
    assert pdf_policy.PROFILES["strong"]["allowJS"] is False


def test_none_profile_allows_everything():
    assert all(pdf_policy.PROFILES["none"].values())


def test_upstream_typo_fixed_flate():
    """upstream uses allowFlateDecode (never matches YAML key) — we use
    allowFlateFilter consistently."""
    assert "allowFlateFilter" in pdf_policy.PROFILES["standard"]
    assert "allowFlateDecode" not in pdf_policy.PROFILES["standard"]


# ---------------------------------------------------------------
# 2. Byte scanner — pdfcop trigger parity
# ---------------------------------------------------------------


def test_scan_detects_launch_action():
    body = b"<< /Type /Action /S /Launch /F (calc.exe) >>"
    findings = pdf_policy.scan(_pdf_with(body))
    actions = [f for f in findings if f.kind == "action"]
    assert any(f.name == "Launch" for f in actions), findings


def test_scan_detects_javascript_action():
    body = b"<< /Type /Action /S /JavaScript /JS (app.alert('hi')) >>"
    findings = pdf_policy.scan(_pdf_with(body))
    assert any(f.name in ("JavaScript", "JavaScript@opening")
               for f in findings if f.kind == "action")


def test_scan_detects_javascript_at_opening():
    body = b"<< /OpenAction << /Type /Action /S /JavaScript /JS (xxx) >> >>"
    findings = pdf_policy.scan(_pdf_with(body))
    js = [f for f in findings if f.kind == "action"
          and "JavaScript" in f.name]
    assert any(f.triggered_at_opening for f in js), js


def test_scan_detects_filter_jbig2():
    body = b"5 0 obj << /Length 100 /Filter /JBIG2Decode >> stream\n...\nendstream endobj"
    findings = pdf_policy.scan(_pdf_with(body))
    assert any(f.name == "JBIG2Decode" for f in findings if f.kind == "filter")


def test_scan_detects_acroform_and_xfa():
    body = b"<< /AcroForm << /Fields [] /XFA 1 0 R >> >>"
    findings = pdf_policy.scan(_pdf_with(body))
    names = {f.name for f in findings if f.kind == "structural"}
    assert "AcroForm" in names
    assert "XFA" in names


def test_scan_detects_annotation_subtypes():
    body = b"<< /Type /Annot /Subtype /FileAttachment >>"
    findings = pdf_policy.scan(_pdf_with(body))
    assert any(f.name == "FileAttachment" for f in findings
               if f.kind == "annotation")


def test_scan_skips_markers_in_comments():
    body = b"%comment with /S /Launch in it\n<< /Type /Catalog >>"
    findings = pdf_policy.scan(_pdf_with(body))
    assert not any(f.name == "Launch" for f in findings)


def test_scan_skips_markers_in_hex_strings():
    body = b"<< /Title <2F532F4C61756E63682F46> >>"  # "/S/Launch/F" hex-encoded
    findings = pdf_policy.scan(_pdf_with(body))
    assert not any(f.name == "Launch" for f in findings)


def test_non_pdf_data_returns_empty():
    assert pdf_policy.scan(b"not a pdf") == []
    assert pdf_policy.scan(b"") == []


# ---------------------------------------------------------------
# 3. Profile evaluator
# ---------------------------------------------------------------


def test_launch_action_blocks_under_standard():
    findings = pdf_policy.scan(_pdf_with(b"<< /S /Launch >>"))
    verdicts = pdf_policy.evaluate(findings, "standard")
    assert any(v.finding.name == "Launch" for v in verdicts)
    assert all(v.severity == Severity.CRITICAL for v in verdicts
               if v.finding.name == "Launch")


def test_launch_action_passes_under_none():
    findings = pdf_policy.scan(_pdf_with(b"<< /S /Launch >>"))
    verdicts = pdf_policy.evaluate(findings, "none")
    assert verdicts == []


def test_uri_action_blocks_only_under_paranoid():
    findings = pdf_policy.scan(_pdf_with(b"<< /S /URI /URI (http://x.example) >>"))
    assert pdf_policy.evaluate(findings, "standard") == []
    assert pdf_policy.evaluate(findings, "strong") == []
    paranoid = pdf_policy.evaluate(findings, "paranoid")
    assert any(v.finding.name == "URI" for v in paranoid)


def test_js_blocks_under_strong_not_standard():
    findings = pdf_policy.scan(_pdf_with(b"<< /S /JavaScript /JS (x) >>"))
    assert pdf_policy.evaluate(findings, "standard") == []
    strong = pdf_policy.evaluate(findings, "strong")
    assert any(v.finding.name == "JavaScript" for v in strong)


def test_all_profiles_verdicts_groups_correctly():
    findings = pdf_policy.scan(_pdf_with(b"<< /S /Launch >> << /S /URI /URI () >>"))
    by_profile = pdf_policy.all_profiles_verdicts(findings)
    assert "standard" in by_profile
    # Launch is blocked under standard; URI only under paranoid
    assert any(v.finding.name == "Launch"
               for v in by_profile["standard"])
    assert all(v.finding.name != "URI"
               for v in by_profile["standard"])
    assert any(v.finding.name == "URI"
               for v in by_profile["paranoid"])


# ---------------------------------------------------------------
# 4. End-to-end — PDFAnalyzer wiring
# ---------------------------------------------------------------


def test_pdf_analyzer_emits_pdfcop_policy_report():
    pytest.importorskip("pypdf")
    body = b"<< /OpenAction << /Type /Action /S /Launch /F (calc.exe) >> >>"
    s = Structure.create(data=_pdf_with(body), filename="t.pdf",
                         mime_type="application/pdf")
    rep = s.analyzer.reports.get("pdfcop_policy")
    assert rep is not None, list(s.analyzer.reports)
    assert "Launch" in rep.text
    # Launch is CRITICAL under all blocking profiles
    assert rep.severity == Severity.CRITICAL
    # All three real profiles should block this PDF
    assert "standard" in rep.text
    assert "strong" in rep.text
    assert "paranoid" in rep.text


def test_pdf_analyzer_no_policy_report_for_clean_pdf():
    pytest.importorskip("pypdf")
    # Just metadata — no actions, no annotations, no exotic filters
    body = b"<< /Title (hello) /Creator (test) >>"
    s = Structure.create(data=_pdf_with(body), filename="t.pdf",
                         mime_type="application/pdf")
    assert "pdfcop_policy" not in s.analyzer.reports
