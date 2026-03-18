"""OOXML helper utilities shared by DocxAnalyzer and XlsxAnalyzer.

Handles common tasks for Office Open XML formats (ZIP-based):
- Document property extraction from docProps/core.xml and docProps/app.xml
- Child filtering to avoid flooding output with noise files
"""

import logging
import xml.etree.ElementTree as ET

log = logging.getLogger("matt")

# Namespaces used in OOXML docProps
_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "dcmitype": "http://purl.org/dc/dcmitype/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
    "vt": "http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes",
}

# Files that are security-relevant and should become child structures
_SECURITY_RELEVANT = {
    ".rels",           # relationship files — external link detection
    "vbaProject.bin",  # VBA macros
}

# Path prefixes for security-relevant directories
_SECURITY_DIRS = (
    "activeX/",
    "embeddings/",
    "externalLinks/",
)

# Noise files to skip as children (themes, styles, fonts, settings, etc.)
_NOISE_PATTERNS = (
    # Word
    "word/theme/",
    "word/styles.xml",
    "word/settings.xml",
    "word/fontTable.xml",
    "word/webSettings.xml",
    "word/numbering.xml",
    "word/footnotes.xml",
    "word/endnotes.xml",
    "word/comments.xml",
    "word/commentsExtended.xml",
    "word/people.xml",
    "word/media/",
    # Excel
    "xl/theme/",
    "xl/styles.xml",
    "xl/sharedStrings.xml",
    "xl/calcChain.xml",
    "xl/printerSettings/",
    # PowerPoint
    "ppt/theme/",
    "ppt/slideLayouts/",
    "ppt/slideMasters/",
    "ppt/presProps.xml",
    "ppt/viewProps.xml",
    "ppt/tableStyles.xml",
    "ppt/media/",
    # Common OOXML structural files (metadata already extracted by analyzers)
    "docProps/core.xml",
    "docProps/app.xml",
    "docProps/thumbnail",
    "[Content_Types].xml",
    "customXml/",
)


def extract_core_properties(zipobj):
    """Extract metadata from docProps/core.xml.

    Returns a dict with keys: title, creator, last_modified_by,
    created, modified, description, subject, category, keywords.
    """
    props = {}
    try:
        raw = zipobj.read("docProps/core.xml")
        root = ET.fromstring(raw)

        _extract = [
            ("title", "dc:title"),
            ("creator", "dc:creator"),
            ("subject", "dc:subject"),
            ("description", "dc:description"),
            ("keywords", "cp:keywords"),
            ("category", "cp:category"),
            ("last_modified_by", "cp:lastModifiedBy"),
            ("revision", "cp:revision"),
        ]
        for key, xpath in _extract:
            elem = root.find(xpath, _NS)
            if elem is not None and elem.text:
                props[key] = elem.text.strip()

        # Dates use dcterms namespace with xsi:type
        for key, xpath in [("created", "dcterms:created"), ("modified", "dcterms:modified")]:
            elem = root.find(xpath, _NS)
            if elem is not None and elem.text:
                props[key] = elem.text.strip()

    except (KeyError, ET.ParseError):
        pass
    except Exception as e:
        log.debug(f"Failed to parse docProps/core.xml: {e}")

    return props


def extract_app_properties(zipobj):
    """Extract metadata from docProps/app.xml.

    Returns a dict with keys like: application, company, app_version,
    pages, words, paragraphs, lines, etc.
    """
    props = {}
    try:
        raw = zipobj.read("docProps/app.xml")
        root = ET.fromstring(raw)

        simple_fields = [
            "Application", "AppVersion", "Company", "Manager",
            "Template", "TotalTime",
            "Pages", "Words", "Characters", "CharactersWithSpaces",
            "Paragraphs", "Lines", "Slides", "Notes",
        ]
        for field in simple_fields:
            elem = root.find(f"ep:{field}", _NS)
            if elem is not None and elem.text:
                props[field.lower()] = elem.text.strip()

        # HeadingPairs + TitleOfParts give sheet/section names
        title_parts_elem = root.find("ep:TitlesOfParts", _NS)
        if title_parts_elem is not None:
            parts = [e.text for e in title_parts_elem.iter(f"{{{_NS['vt']}}}lpstr") if e.text]
            if parts:
                props["parts"] = parts

    except (KeyError, ET.ParseError):
        pass
    except Exception as e:
        log.debug(f"Failed to parse docProps/app.xml: {e}")

    return props


def is_security_relevant(filepath):
    """Return True if an internal OOXML file is security-relevant."""
    basename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath

    if basename in _SECURITY_RELEVANT:
        return True

    # .rels files can have any prefix (e.g. document.xml.rels)
    if basename.endswith(".rels"):
        return True

    # Check security-relevant directories
    for d in _SECURITY_DIRS:
        if d in filepath:
            return True

    # Main document/workbook XML files (DDE, XXE detection)
    if basename.endswith(".xml"):
        return True

    return False


def is_noise_file(filepath):
    """Return True if a file is structural noise (themes, styles, etc.)."""
    for pattern in _NOISE_PATTERNS:
        if filepath.startswith(pattern):
            return True
    return False


def should_create_child(filepath):
    """Decide whether an internal OOXML file should become a child Structure."""
    if filepath.endswith("/"):
        return False
    if is_noise_file(filepath):
        return False
    return is_security_relevant(filepath)
