"""
Unified Office Document Analyzer (OOXML).

Handles DOCX, XLSX, PPTX and their macro-enabled variants end-to-end.
Performs all forensic analysis inline (relationships, XML threats, VBA,
structural checks, metadata, IOC extraction) and only emits children
for truly interesting items: embedded objects, VBA binaries, ActiveX
binaries, and orphan files.

Falls back to ZipAnalyzer if it cannot parse the document.
"""

import io
import logging
import os
import re
import xml.etree.ElementTree as ET
import zipfile

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

# Try to import IOC extractor
try:
    from Utils.ioc_extractor import extract_iocs

    _IOC_AVAILABLE = True
except ImportError:
    _IOC_AVAILABLE = False

# OOXML relationship namespace
_RELS_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}

# Dublin Core / docProps namespaces
_DC_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
}
_APP_NS = {
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}

# OOXML document content namespaces
_WORD_NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
_EXCEL_NS = {"s": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_PPT_NS = {"a": "http://schemas.openxmlformats.org/drawingml/2006/main"}


class OfficeDocumentAnalyzer(Analyzer):
    """
    Unified OOXML analyzer.  Replaces the old DocxAnalyzer + child-dispatch
    approach with a single-pass analysis that reports all findings inline
    and only emits children for embedded objects and orphan files.
    """

    compatible_mime_types = [
        # Word
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-word.document.macroEnabled.12",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.template",
        "application/vnd.ms-word.template.macroEnabled.12",
        # Excel
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.template",
        "application/vnd.ms-excel.template.macroEnabled.12",
        "application/vnd.ms-excel.addin.macroEnabled.12",
        # PowerPoint
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
        "application/vnd.openxmlformats-officedocument.presentationml.template",
        "application/vnd.ms-powerpoint.template.macroEnabled.12",
        "application/vnd.openxmlformats-officedocument.presentationml.slideshow",
        "application/vnd.ms-powerpoint.slideshow.macroEnabled.12",
        "application/vnd.ms-powerpoint.addin.macroEnabled.12",
    ]

    description = "Office Document Analyzer (DOCX/XLSX/PPTX)"

    # If we fail, let ZipAnalyzer have a go
    fallback_analyzer = None  # resolved lazily to avoid circular import

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Detect OOXML inside a generic application/zip.

        OOXML files are ZIP archives that always contain
        [Content_Types].xml at the root.
        """
        if not struct.rawdata or len(struct.rawdata) < 4:
            return False
        # Must start with ZIP magic
        if struct.rawdata[:4] != b"PK\x03\x04":
            return False
        try:
            with zipfile.ZipFile(io.BytesIO(struct.rawdata)) as zf:
                return "[Content_Types].xml" in zf.namelist()
        except Exception:
            return False

    def _resolve_fallback(self):
        """Lazily resolve fallback to ZipAnalyzer (avoids circular import)."""
        if OfficeDocumentAnalyzer.fallback_analyzer is None:
            from Analyzers.ZipAnalyzer import ZipAnalyzer
            OfficeDocumentAnalyzer.fallback_analyzer = ZipAnalyzer

    def analysis(self):
        super().analysis()
        self._resolve_fallback()
        self.success = True

        # --- Open as ZIP ---
        try:
            fobj = io.BytesIO(self.struct.rawdata)
            self._zip = zipfile.ZipFile(fobj)
            self._namelist = self._zip.namelist()
        except zipfile.BadZipFile:
            self.reports["error"] = Report(
                "Invalid Office document (not a valid ZIP archive).",
                severity=Severity.HIGH,
            )
            self.success = False
            return
        except Exception as e:
            self.reports["error"] = Report(
                f"Failed to open Office document: {e}",
                severity=Severity.HIGH,
            )
            self.success = False
            return

        self.info = f"Office document — {len(self._namelist)} internal parts"

        # Collect all referenced targets from .rels files
        self._referenced_targets = set()

        # Run all analysis modules
        self._analyze_structure()
        self._analyze_relationships()
        self._analyze_xml_content()
        self._analyze_vba()
        self._analyze_metadata()
        self._extract_text_and_iocs()
        self._detect_orphans_and_emit_children()

    # ------------------------------------------------------------------
    # Structural analysis (ActiveX dirs, OLE objects, embedded fonts)
    # ------------------------------------------------------------------
    def _analyze_structure(self):
        activex_files = [f for f in self._namelist if "/activeX/" in f and f.endswith(".xml")]
        if activex_files:
            self.reports["activeX"] = Report(
                f"ActiveX controls found: {', '.join(os.path.basename(f) for f in activex_files)}",
                severity=Severity.MEDIUM,
            )

        ole_files = [f for f in self._namelist if "/embeddings/" in f]
        if ole_files:
            self.reports["ole_objects"] = Report(
                f"Embedded OLE objects: {', '.join(os.path.basename(f) for f in ole_files)}",
                severity=Severity.HIGH,
            )

        font_files = [f for f in self._namelist if "/fonts/" in f and not f.endswith("/")]
        if font_files:
            self.reports["embedded_fonts"] = Report(
                f"Embedded fonts: {', '.join(os.path.basename(f) for f in font_files)}",
                severity=Severity.MEDIUM,
            )

    # ------------------------------------------------------------------
    # Relationship analysis (absorbs OfficeRelationshipAnalyzer)
    # ------------------------------------------------------------------
    def _analyze_relationships(self):
        rels_files = [f for f in self._namelist if f.endswith(".rels")]

        for rels_path in rels_files:
            try:
                xml_bytes = self._zip.read(rels_path)
                root = ET.fromstring(xml_bytes)
            except (ET.ParseError, Exception) as e:
                log.debug(f"Could not parse {rels_path}: {e}")
                continue

            rels_dir = os.path.dirname(rels_path)
            # The .rels file sits in _rels/, targets are relative to parent dir
            parent_dir = os.path.dirname(rels_dir) if rels_dir.endswith("_rels") else rels_dir

            for rel in root.findall("r:Relationship", _RELS_NS):
                target = rel.get("Target", "")
                target_mode = rel.get("TargetMode", "Internal")
                rel_type = rel.get("Type", "")

                # Track referenced internal targets for orphan detection
                if target_mode != "External" and target:
                    # Resolve relative path
                    if not target.startswith("/"):
                        resolved = os.path.normpath(os.path.join(parent_dir, target)).replace("\\", "/")
                    else:
                        resolved = target.lstrip("/")
                    self._referenced_targets.add(resolved)

                # Check for external relationships (security threats)
                if target_mode == "External":
                    rel_type_suffix = rel_type.split("/")[-1]
                    key = f"ext_rel_{rels_path}_{rel.get('Id', '')}"

                    if "attachedTemplate" in rel_type:
                        self.reports[key] = Report(
                            f"Remote Template Injection detected. Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif target.startswith("file://"):
                        self.reports[key] = Report(
                            f"Potential NTLM hash leak via file:// link. Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif "altChunk" in rel_type:
                        self.reports[key] = Report(
                            f"External altChunk can import external content. Target: {target}",
                            severity=Severity.HIGH,
                        )
                    else:
                        self.reports[key] = Report(
                            f"External link of type '{rel_type_suffix}'. Target: {target}",
                            severity=Severity.HIGH,
                        )

    # ------------------------------------------------------------------
    # XML content analysis (absorbs OfficeXMLAnalyzer)
    # ------------------------------------------------------------------
    def _analyze_xml_content(self):
        xml_files = [
            f for f in self._namelist
            if f.endswith(".xml") and not f.endswith(".rels") and f != "[Content_Types].xml"
        ]

        suspicious_patterns = {
            r"\bDDE\b": "DDE field",
            r"\bDDEAUTO\b": "DDE Auto-execution",
        }

        for xml_path in xml_files:
            try:
                content = self._zip.read(xml_path).decode("utf-8", errors="ignore")
            except Exception:
                continue

            # Line-based scans: DDE, XXE
            for line_num, line in enumerate(content.splitlines(), 1):
                if "<!ENTITY" in line:
                    key = f"xxe_{xml_path}_{line_num}"
                    self.reports[key] = Report(
                        f"Potential XXE injection in {xml_path} line {line_num}: {line.strip()[:120]}",
                        severity=Severity.CRITICAL,
                    )
                for pattern, desc in suspicious_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        key = f"dde_{xml_path}_{line_num}"
                        self.reports[key] = Report(
                            f"Suspicious string ({desc}) in {xml_path} line {line_num}: {line.strip()[:120]}",
                            severity=Severity.CRITICAL,
                        )

            # XML-parsed checks: suspicious tags
            try:
                root = ET.fromstring(content.encode("utf-8"))
                ns = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
                suspicious_tags = {
                    "w:subDoc": "Sub-document inclusion",
                    "w:control": "ActiveX Control",
                }
                for tag, desc in suspicious_tags.items():
                    if root.findall(f".//{tag}", ns):
                        self.reports[f"tag_{xml_path}_{tag}"] = Report(
                            f"Suspicious tag '{tag}' ({desc}) found in {xml_path}.",
                            severity=Severity.HIGH,
                        )
            except ET.ParseError:
                pass

            # Custom XML payload detection
            if "customXml" in xml_path:
                match = re.search(r"[A-Za-z0-9+/=]{50,}", content)
                if match:
                    excerpt = match.group(0)[:75]
                    self.reports[f"customxml_payload_{xml_path}"] = Report(
                        f"Potentially encoded payload in {xml_path}. Excerpt: {excerpt}...",
                        severity=Severity.HIGH,
                    )

    # ------------------------------------------------------------------
    # VBA detection
    # ------------------------------------------------------------------
    def _analyze_vba(self):
        vba_files = [f for f in self._namelist if "vbaProject.bin" in f]
        if vba_files:
            self.reports["vba_macros"] = Report(
                f"Document contains VBA macros ({', '.join(vba_files)}).",
                severity=Severity.CRITICAL,
            )

    # ------------------------------------------------------------------
    # Metadata extraction from docProps/core.xml and docProps/app.xml
    # ------------------------------------------------------------------
    def _analyze_metadata(self):
        findings = []

        # --- core.xml (Dublin Core: author, dates, title, etc.) ---
        if "docProps/core.xml" in self._namelist:
            try:
                raw = self._zip.read("docProps/core.xml")
                root = ET.fromstring(raw)

                core_fields = {
                    "creator": f"{{{_DC_NS['dc']}}}creator",
                    "last_modified_by": f"{{{_DC_NS['cp']}}}lastModifiedBy",
                    "revision": f"{{{_DC_NS['cp']}}}revision",
                    "title": f"{{{_DC_NS['dc']}}}title",
                    "subject": f"{{{_DC_NS['dc']}}}subject",
                    "description": f"{{{_DC_NS['dc']}}}description",
                    "created": f"{{{_DC_NS['dcterms']}}}created",
                    "modified": f"{{{_DC_NS['dcterms']}}}modified",
                }

                for label, tag in core_fields.items():
                    el = root.find(tag)
                    if el is not None and el.text and el.text.strip():
                        findings.append(f"{label}: {el.text.strip()}")
            except Exception as e:
                log.debug(f"Could not parse docProps/core.xml: {e}")

        # --- app.xml (Application, Company, Template, etc.) ---
        if "docProps/app.xml" in self._namelist:
            try:
                raw = self._zip.read("docProps/app.xml")
                root = ET.fromstring(raw)
                ns = _APP_NS["ep"]

                app_fields = {
                    "application": f"{{{ns}}}Application",
                    "app_version": f"{{{ns}}}AppVersion",
                    "company": f"{{{ns}}}Company",
                    "template": f"{{{ns}}}Template",
                    "total_time": f"{{{ns}}}TotalTime",
                    "pages": f"{{{ns}}}Pages",
                    "words": f"{{{ns}}}Words",
                }

                template_value = None
                for label, tag in app_fields.items():
                    el = root.find(tag)
                    if el is not None and el.text and el.text.strip():
                        findings.append(f"{label}: {el.text.strip()}")
                        if label == "template":
                            template_value = el.text.strip()

                # Flag suspicious templates
                if template_value:
                    tl = template_value.lower()
                    if tl.startswith("http") or tl.startswith("\\\\") or tl.startswith("//"):
                        self.reports["remote_template_meta"] = Report(
                            f"Metadata references remote template: {template_value}",
                            severity=Severity.CRITICAL,
                        )
            except Exception as e:
                log.debug(f"Could not parse docProps/app.xml: {e}")

        if findings:
            self.reports["metadata"] = Report(
                "\n".join(findings),
                label="Document metadata",
            )

    # ------------------------------------------------------------------
    # Text extraction and IOC scanning
    # ------------------------------------------------------------------
    def _extract_text_and_iocs(self):
        """Extract visible text from the document and scan for IOCs."""
        text_parts = []

        for filepath in self._namelist:
            # Word: word/document.xml
            if filepath in ("word/document.xml", "word/document2.xml"):
                text_parts.extend(self._extract_word_text(filepath))
            # Excel: xl/sharedStrings.xml has all string cell values
            elif filepath == "xl/sharedStrings.xml":
                text_parts.extend(self._extract_excel_text(filepath))
            # PowerPoint: ppt/slides/slide*.xml
            elif filepath.startswith("ppt/slides/slide") and filepath.endswith(".xml"):
                text_parts.extend(self._extract_ppt_text(filepath))

        if not text_parts:
            return

        full_text = "\n".join(text_parts)

        if not _IOC_AVAILABLE or not full_text.strip():
            return

        try:
            iocs = extract_iocs(full_text)
            if iocs.has_findings:
                parts = iocs.summary_parts()
                detail_lines = []
                if iocs.ipv4:
                    detail_lines.append(f"IPv4: {', '.join(iocs.ipv4)}")
                if iocs.ipv6:
                    detail_lines.append(f"IPv6: {', '.join(iocs.ipv6)}")
                if iocs.urls:
                    detail_lines.append(f"URLs: {', '.join(iocs.urls)}")
                if iocs.emails:
                    detail_lines.append(f"Emails: {', '.join(iocs.emails)}")
                if iocs.domains:
                    detail_lines.append(f"Domains: {', '.join(iocs.domains)}")
                if iocs.md5:
                    detail_lines.append(f"MD5: {', '.join(iocs.md5)}")
                if iocs.sha1:
                    detail_lines.append(f"SHA1: {', '.join(iocs.sha1)}")
                if iocs.sha256:
                    detail_lines.append(f"SHA256: {', '.join(iocs.sha256)}")
                if iocs.passwords:
                    detail_lines.append(f"Passwords: {', '.join(iocs.passwords)}")

                self.reports["iocs"] = Report(
                    "\n".join(detail_lines),
                    short=", ".join(parts),
                    label="iocs",
                    severity=Severity.MEDIUM if (iocs.urls or iocs.ipv4) else Severity.INFO,
                )
        except Exception as e:
            log.debug(f"IOC extraction failed: {e}")

    def _extract_word_text(self, path):
        """Extract text runs from a Word document.xml."""
        texts = []
        try:
            raw = self._zip.read(path)
            root = ET.fromstring(raw)
            for t_el in root.iter(f"{{{_WORD_NS['w']}}}t"):
                if t_el.text:
                    texts.append(t_el.text)
        except Exception:
            pass
        return texts

    def _extract_excel_text(self, path):
        """Extract shared strings from Excel."""
        texts = []
        try:
            raw = self._zip.read(path)
            root = ET.fromstring(raw)
            for t_el in root.iter(f"{{{_EXCEL_NS['s']}}}t"):
                if t_el.text:
                    texts.append(t_el.text)
        except Exception:
            pass
        return texts

    def _extract_ppt_text(self, path):
        """Extract text from a PowerPoint slide."""
        texts = []
        try:
            raw = self._zip.read(path)
            root = ET.fromstring(raw)
            for t_el in root.iter(f"{{{_PPT_NS['a']}}}t"):
                if t_el.text:
                    texts.append(t_el.text)
        except Exception:
            pass
        return texts

    # ------------------------------------------------------------------
    # Orphan detection + child emission (combined to avoid duplication)
    # ------------------------------------------------------------------
    def _detect_orphans_and_emit_children(self):
        # Build normalized set of referenced targets once
        normalized_refs = set()
        for ref in self._referenced_targets:
            normalized_refs.add(ref.replace("\\", "/").lstrip("/"))
        # Standard infrastructure files are never orphans
        normalized_refs.add("[Content_Types].xml")

        idx = 0
        for filepath in self._namelist:
            if filepath.endswith("/"):
                continue

            emit = False
            is_orphan = False

            # Check embedding/activeX directories (binary files only)
            if ("/embeddings/" in filepath or "/activeX/" in filepath) and \
               not filepath.endswith(".xml") and not filepath.endswith(".rels"):
                emit = True

            # VBA project binaries
            if "vbaProject.bin" in filepath:
                emit = True

            # Orphan detection — skip infrastructure files
            if not filepath.endswith(".rels") and \
               "/_rels/" not in filepath and not filepath.startswith("_rels/") and \
               filepath != "[Content_Types].xml" and not filepath.startswith("docProps/"):
                normalized = filepath.replace("\\", "/").lstrip("/")
                if normalized not in normalized_refs:
                    is_orphan = True
                    emit = True
                    self.reports[f"orphan_{filepath}"] = Report(
                        f"Unreferenced file (orphan): {filepath}",
                        severity=Severity.MEDIUM,
                    )

            if emit:
                try:
                    child_data = self._zip.read(filepath)
                    child_struct = self.generate_struct(
                        filename=filepath, data=child_data, index=idx,
                    )
                    child_struct.parent = self.struct
                    self.childitems.append(child_struct)
                    idx += 1
                except Exception as e:
                    self.reports[f"child_error_{filepath}"] = Report(
                        f"Error extracting {filepath}: {e}",
                        severity=Severity.MEDIUM,
                    )
