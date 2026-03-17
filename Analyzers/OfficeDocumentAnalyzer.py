"""
Unified Office Document Analyzer (OOXML).

Handles DOCX, XLSX, PPTX and their macro-enabled variants end-to-end.
Performs all forensic analysis inline (relationships, XML threats, VBA,
structural checks) and only emits children for truly interesting items:
embedded objects, VBA binaries, ActiveX binaries, and orphan files.

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

# OOXML relationship namespace
_RELS_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}

# Well-known internal paths that are never interesting as children
_BOILERPLATE_PREFIXES = (
    "[Content_Types].xml",
    "_rels/",
    "docProps/",
)

# Standard content directories per format — XML parts we analyze inline
_CONTENT_DIRS = {
    "word/",
    "xl/",
    "ppt/",
    "customXml/",
}

# Directories whose *binary* files are interesting children
_EMBEDDING_DIRS = (
    "word/embeddings/",
    "xl/embeddings/",
    "ppt/embeddings/",
    "word/activeX/",
    "xl/activeX/",
    "ppt/activeX/",
    "word/media/",
    "xl/media/",
    "ppt/media/",
)


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
        # Excel
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.ms-excel.sheet.macroEnabled.12",
        # PowerPoint
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    ]

    description = "Office Document Analyzer (DOCX/XLSX/PPTX)"

    # If we fail, let ZipAnalyzer have a go
    fallback_analyzer = None  # resolved lazily to avoid circular import

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
        self._detect_orphans()
        self._emit_children()

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
                severity=Severity.CRITICAL,
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
            if f.endswith(".xml") and not f.endswith(".rels") and not f == "[Content_Types].xml"
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
    # Orphan file detection (files not referenced by any .rels)
    # ------------------------------------------------------------------
    def _detect_orphans(self):
        # Normalize referenced targets
        normalized_refs = set()
        for ref in self._referenced_targets:
            normalized_refs.add(ref.replace("\\", "/").lstrip("/"))

        # Also add well-known always-present files
        normalized_refs.add("[Content_Types].xml")

        for filepath in self._namelist:
            if filepath.endswith("/"):
                continue
            # .rels files are infrastructure, not orphans
            if filepath.endswith(".rels"):
                continue
            # _rels directories are infrastructure
            if "/_rels/" in filepath or filepath.startswith("_rels/"):
                continue
            # [Content_Types].xml
            if filepath == "[Content_Types].xml":
                continue
            # docProps are standard
            if filepath.startswith("docProps/"):
                continue

            normalized = filepath.replace("\\", "/").lstrip("/")
            if normalized not in normalized_refs:
                self.reports[f"orphan_{filepath}"] = Report(
                    f"Unreferenced file (orphan): {filepath}",
                    severity=Severity.MEDIUM,
                )

    # ------------------------------------------------------------------
    # Emit children only for interesting items
    # ------------------------------------------------------------------
    def _emit_children(self):
        idx = 0
        for filepath in self._namelist:
            if filepath.endswith("/"):
                continue

            emit = False

            # Embedded objects (OLE, media in embeddings dirs)
            if any(filepath.startswith(d) or f"/{d.split('/')[-2]}/" in filepath
                   for d in _EMBEDDING_DIRS if not filepath.endswith(".xml") and not filepath.endswith(".rels")):
                # Simpler check: is it in an embeddings/ or activeX/ directory
                # and is it a binary (not xml/rels)?
                pass

            # Check embedding/activeX directories (binary files only)
            if ("/embeddings/" in filepath or "/activeX/" in filepath) and \
               not filepath.endswith(".xml") and not filepath.endswith(".rels"):
                emit = True

            # VBA project binaries
            if "vbaProject.bin" in filepath:
                emit = True

            # Orphan files (unreferenced = suspicious, worth deeper analysis)
            normalized = filepath.replace("\\", "/").lstrip("/")
            normalized_refs = set()
            for ref in self._referenced_targets:
                normalized_refs.add(ref.replace("\\", "/").lstrip("/"))
            # Add standard infrastructure
            if filepath.endswith(".rels") or "/_rels/" in filepath or filepath.startswith("_rels/"):
                pass
            elif filepath == "[Content_Types].xml" or filepath.startswith("docProps/"):
                pass
            elif normalized not in normalized_refs:
                emit = True

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
