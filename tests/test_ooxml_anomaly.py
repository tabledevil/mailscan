"""Tests for OOXML structural anomaly detection enhancements.

Covers: path traversal, Content_Types validation, relationship integrity,
XML structural heuristics, and embedded CLSID scanning.
"""

import io
import os
import struct
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear_caches():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# ===================================================================
# Helpers — minimal DOCX / ZIP builders
# ===================================================================

_MINIMAL_CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" '
    'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>'
)

_MINIMAL_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
    'Target="word/document.xml"/>'
    '</Relationships>'
)

_MINIMAL_DOCUMENT = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:body><w:p><w:r><w:t>Hello</w:t></w:r></w:p></w:body></w:document>'
)


def _build_docx(**extra_files):
    """Build a minimal DOCX (ZIP) in memory. extra_files: {path: bytes_content}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", extra_files.pop("[Content_Types].xml", _MINIMAL_CONTENT_TYPES))
        zf.writestr("_rels/.rels", extra_files.pop("_rels/.rels", _MINIMAL_RELS))
        zf.writestr("word/document.xml", extra_files.pop("word/document.xml", _MINIMAL_DOCUMENT))
        for path, data in extra_files.items():
            zf.writestr(path, data)
    return buf.getvalue()


def _make_struct(data, *, mime_type=None, filename=None):
    return Structure.create(data=data, filename=filename, mime_type=mime_type)


# ===================================================================
# Fixtures
# ===================================================================

@pytest.fixture
def docx_normal_bytes():
    return _build_docx()


@pytest.fixture
def zip_path_traversal_bytes():
    """ZIP with ../../etc/passwd member."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../etc/passwd", b"root:x:0:0::/root:/bin/bash")
        zf.writestr("legit.txt", b"normal file")
    return buf.getvalue()


@pytest.fixture
def docx_path_traversal_bytes():
    """DOCX with ../evil.xml extra file."""
    return _build_docx(**{"../evil.xml": b"<evil/>"})


@pytest.fixture
def docx_phantom_part_bytes():
    """Override for a PartName that doesn't exist in the archive."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/phantom.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '</Types>'
    )
    return _build_docx(**{"[Content_Types].xml": ct})


@pytest.fixture
def docx_undeclared_file_bytes():
    """Extra .bin file with no Content_Types entry."""
    return _build_docx(**{"word/secret.bin": b"\x00" * 100})


@pytest.fixture
def docx_conflicting_overrides_bytes():
    """Two Override elements for the same PartName, different ContentTypes."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.ms-word.document.macroEnabled.12"/>'
        '</Types>'
    )
    return _build_docx(**{"[Content_Types].xml": ct})


@pytest.fixture
def docx_unusual_ct_bytes():
    """ContentType application/x-shellcode."""
    ct = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        '<Override PartName="/word/payload.bin" '
        'ContentType="application/x-shellcode"/>'
        '</Types>'
    )
    return _build_docx(**{"word/payload.bin": b"\xcc" * 50, "[Content_Types].xml": ct})


@pytest.fixture
def docx_dangling_ref_bytes():
    """Relationship pointing to a target that doesn't exist in the ZIP."""
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        '<Relationship Id="rId2" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/image" '
        'Target="word/media/missing_image.png"/>'
        '</Relationships>'
    )
    return _build_docx(**{"_rels/.rels": rels})


@pytest.fixture
def docx_deep_nesting_bytes():
    """XML with 60 levels of nested elements."""
    inner = "<w:t>deep</w:t>"
    for i in range(60):
        inner = f"<w:r>{inner}</w:r>"
    doc = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body><w:p>{inner}</w:p></w:body></w:document>'
    )
    return _build_docx(**{"word/document.xml": doc})


@pytest.fixture
def docx_large_blob_bytes():
    """600-char base64 string in document.xml."""
    blob = "A" * 600
    doc = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:body><w:p><w:r><w:t>{blob}</w:t></w:r></w:p></w:body></w:document>'
    )
    return _build_docx(**{"word/document.xml": doc})


@pytest.fixture
def docx_mc_heavy_bytes():
    """15 mc:AlternateContent elements in document.xml."""
    mc_block = (
        '<mc:AlternateContent xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">'
        '<mc:Choice Requires="w14"><w:r><w:t>new</w:t></w:r></mc:Choice>'
        '<mc:Fallback><w:r><w:t>old</w:t></w:r></mc:Fallback>'
        '</mc:AlternateContent>'
    )
    doc = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
        'xmlns:mc="http://schemas.openxmlformats.org/markup-compatibility/2006">'
        f'<w:body><w:p>{"".join([mc_block] * 15)}</w:p></w:body></w:document>'
    )
    return _build_docx(**{"word/document.xml": doc})


@pytest.fixture
def docx_equation_editor_bytes():
    """Embedding file containing the Equation Editor CLSID bytes."""
    # Equation Editor 3.0 CLSID: 0002ce02-0000-0000-c000-000000000046
    clsid_bytes = struct.pack("<IHH", 0x0002ce02, 0x0000, 0x0000) + bytes.fromhex("c000000000000046")
    # Pad with OLE magic + the CLSID somewhere inside
    ole_data = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1" + b"\x00" * 20 + clsid_bytes + b"\x00" * 100
    return _build_docx(**{"word/embeddings/oleObject1.bin": ole_data})


# ===================================================================
# Enhancement 1: ZIP Path Traversal
# ===================================================================

class TestZipPathTraversal:
    def test_zip_traversal_detected(self, zip_path_traversal_bytes):
        s = _make_struct(zip_path_traversal_bytes, mime_type="application/zip")
        reports = s.analyzer.reports
        assert "path_traversal" in reports
        assert reports["path_traversal"].severity == Severity.CRITICAL

    def test_docx_traversal_detected(self, docx_path_traversal_bytes):
        s = _make_struct(
            docx_path_traversal_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        # Check OfficeDocumentAnalyzer's report
        all_reports = s.analyzer.reports
        assert "zip_path_traversal" in all_reports
        assert all_reports["zip_path_traversal"].severity == Severity.CRITICAL

    def test_normal_zip_no_traversal(self, docx_normal_bytes):
        s = _make_struct(docx_normal_bytes, mime_type="application/zip")
        assert "path_traversal" not in s.analyzer.reports


# ===================================================================
# Enhancement 2: Content_Types Deep Validation
# ===================================================================

class TestContentTypesValidation:
    def test_phantom_parts_detected(self, docx_phantom_part_bytes):
        s = _make_struct(
            docx_phantom_part_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "phantom_content_parts" in all_reports
        assert all_reports["phantom_content_parts"].severity == Severity.MEDIUM

    def test_undeclared_parts_detected(self, docx_undeclared_file_bytes):
        s = _make_struct(
            docx_undeclared_file_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "undeclared_parts" in all_reports
        assert all_reports["undeclared_parts"].severity == Severity.MEDIUM

    def test_conflicting_overrides_detected(self, docx_conflicting_overrides_bytes):
        s = _make_struct(
            docx_conflicting_overrides_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "content_type_conflict" in all_reports
        assert all_reports["content_type_conflict"].severity == Severity.HIGH

    def test_unusual_content_type_detected(self, docx_unusual_ct_bytes):
        s = _make_struct(
            docx_unusual_ct_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "unusual_content_type" in all_reports
        assert all_reports["unusual_content_type"].severity == Severity.LOW

    def test_normal_docx_no_content_type_issues(self, docx_normal_bytes):
        s = _make_struct(
            docx_normal_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "phantom_content_parts" not in all_reports
        assert "content_type_conflict" not in all_reports
        assert "unusual_content_type" not in all_reports


# ===================================================================
# Enhancement 3: Relationship Integrity
# ===================================================================

class TestRelationshipIntegrity:
    def test_dangling_reference_detected(self, docx_dangling_ref_bytes):
        s = _make_struct(
            docx_dangling_ref_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "dangling_references" in all_reports
        assert all_reports["dangling_references"].severity == Severity.MEDIUM

    def test_normal_docx_no_dangling(self, docx_normal_bytes):
        s = _make_struct(
            docx_normal_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "dangling_references" not in all_reports


# ===================================================================
# Enhancement 4: XML Structural Heuristics
# ===================================================================

class TestXMLStructuralHeuristics:
    def test_deep_nesting_detected(self, docx_deep_nesting_bytes):
        s = _make_struct(
            docx_deep_nesting_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        nesting_reports = [k for k in all_reports if k.startswith("deep_nesting_")]
        assert len(nesting_reports) >= 1
        assert all_reports[nesting_reports[0]].severity == Severity.MEDIUM

    def test_large_blob_detected(self, docx_large_blob_bytes):
        s = _make_struct(
            docx_large_blob_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        blob_reports = [k for k in all_reports if k.startswith("large_blob_")]
        assert len(blob_reports) >= 1
        assert all_reports[blob_reports[0]].severity == Severity.MEDIUM

    def test_mc_heavy_detected(self, docx_mc_heavy_bytes):
        s = _make_struct(
            docx_mc_heavy_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        mc_reports = [k for k in all_reports if k.startswith("mc_heavy_")]
        assert len(mc_reports) >= 1
        assert all_reports[mc_reports[0]].severity == Severity.MEDIUM

    def test_normal_docx_no_xml_issues(self, docx_normal_bytes):
        s = _make_struct(
            docx_normal_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert not any(k.startswith("deep_nesting_") for k in all_reports)
        assert not any(k.startswith("large_blob_") for k in all_reports)
        assert not any(k.startswith("mc_heavy_") for k in all_reports)


# ===================================================================
# Enhancement 5: Embedded CLSID Scan
# ===================================================================

class TestEmbeddedCLSID:
    def test_equation_editor_clsid_detected(self, docx_equation_editor_bytes):
        s = _make_struct(
            docx_equation_editor_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        clsid_reports = [k for k in all_reports if k.startswith("embedded_clsid_")]
        assert len(clsid_reports) >= 1
        assert all_reports[clsid_reports[0]].severity == Severity.CRITICAL
        assert "Equation Editor" in all_reports[clsid_reports[0]].text

    def test_normal_docx_no_clsid_alert(self, docx_normal_bytes):
        s = _make_struct(
            docx_normal_bytes,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert not any(k.startswith("embedded_clsid_") for k in all_reports)


# ===================================================================
# Edge cases and regression tests
# ===================================================================

class TestEdgeCases:
    def test_backslash_path_traversal_in_zip(self):
        """Backslash traversal paths should also be detected."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            # ZipInfo allows setting arbitrary filenames
            zf.writestr("normal.txt", b"ok")
            zf.writestr("foo\\..\\..\\evil.exe", b"\x4d\x5a")
        data = buf.getvalue()
        s = _make_struct(data, mime_type="application/zip")
        assert "path_traversal" in s.analyzer.reports

    def test_customxml_blob_no_large_blob_duplicate(self):
        """customXml files should NOT trigger large_blob (only customxml_payload)."""
        blob = "B" * 600
        custom_xml = f'<?xml version="1.0"?><root>{blob}</root>'
        docx = _build_docx(**{"customXml/item1.xml": custom_xml})
        s = _make_struct(
            docx,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        # Should have customxml_payload but NOT large_blob for the same file
        customxml_keys = [k for k in all_reports if "customxml_payload" in k]
        large_blob_keys = [k for k in all_reports if k.startswith("large_blob_") and "customXml" in k]
        assert len(customxml_keys) >= 1
        assert len(large_blob_keys) == 0

    def test_nonstandard_rel_type_detected(self):
        """Relationship with a non-standard Type URI should be flagged."""
        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
            'Target="word/document.xml"/>'
            '<Relationship Id="rId99" '
            'Type="http://evil.example.com/custom/exploit" '
            'Target="word/payload.xml"/>'
            '</Relationships>'
        )
        docx = _build_docx(**{"_rels/.rels": rels, "word/payload.xml": b"<x/>"})
        s = _make_struct(
            docx,
            mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        )
        all_reports = s.analyzer.reports
        assert "nonstandard_rel_type" in all_reports
        assert all_reports["nonstandard_rel_type"].severity == Severity.LOW

    def test_absolute_path_in_zip(self):
        """Absolute paths in ZIP should be flagged as HIGH."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("/etc/shadow", b"root:!::")
            zf.writestr("normal.txt", b"ok")
        data = buf.getvalue()
        s = _make_struct(data, mime_type="application/zip")
        assert "absolute_path" in s.analyzer.reports
        assert s.analyzer.reports["absolute_path"].severity == Severity.HIGH
