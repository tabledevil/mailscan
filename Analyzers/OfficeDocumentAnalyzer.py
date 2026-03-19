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
import struct as struct_mod
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

# Try to import VBA extractor
try:
    from Utils.vba_extractor import extract_vba_from_ole_data

    _VBA_AVAILABLE = True
except ImportError:
    _VBA_AVAILABLE = False

# Try to import OLE Package parser
try:
    from Utils.ole_package import parse_embedded_object

    _OLEPACKAGE_AVAILABLE = True
except ImportError:
    _OLEPACKAGE_AVAILABLE = False

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


def _clsid_str_to_bytes(clsid_str):
    """Convert a CLSID string (e.g. '0002ce02-0000-...') to its little-endian binary form."""
    parts = clsid_str.split("-")
    # GUID binary: Data1 (LE 32), Data2 (LE 16), Data3 (LE 16), Data4 (8 bytes big-endian)
    d1 = int(parts[0], 16)
    d2 = int(parts[1], 16)
    d3 = int(parts[2], 16)
    d4 = bytes.fromhex(parts[3] + parts[4])
    return struct_mod.pack("<IHH", d1, d2, d3) + d4


def _measure_xml_depth(root):
    """Iteratively measure maximum nesting depth of an ElementTree."""
    max_depth = 0
    stack = [(root, 1)]
    while stack:
        elem, depth = stack.pop()
        if depth > max_depth:
            max_depth = depth
        for child in elem:
            stack.append((child, depth + 1))
    return max_depth


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
    specificity = 20

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

        # Path traversal check
        traversal_paths = [
            n for n in self._namelist
            if ".." in n.replace("\\", "/").split("/")
        ]
        if traversal_paths:
            self.reports["zip_path_traversal"] = Report(
                f"Path traversal in OOXML archive: {', '.join(traversal_paths[:10])}",
                severity=Severity.CRITICAL,
            )

        # Collect all referenced targets from .rels files
        self._referenced_targets = set()

        # Run all analysis modules
        self._analyze_content_types()
        self._analyze_structure()
        self._analyze_relationships()
        self._analyze_xml_content()
        self._analyze_vba()
        self._check_embedded_clsids()
        self._analyze_metadata()
        self._extract_text_and_iocs()
        self._detect_hyperlink_abuse()
        self._detect_svg_scripts()
        self._detect_orphans_and_emit_children()

    # ------------------------------------------------------------------
    # Content-Type validation — flag VBA in non-macro extensions
    # ------------------------------------------------------------------
    def _analyze_content_types(self):
        if "[Content_Types].xml" not in self._namelist:
            return
        try:
            raw = self._zip.read("[Content_Types].xml").decode("utf-8", errors="ignore")
            root = ET.fromstring(raw.encode("utf-8"))
        except Exception:
            return

        has_vba_content_type = False
        for elem in root:
            ct = elem.get("ContentType", "")
            if "vbaProject" in ct or "macroEnabled" in ct.lower():
                has_vba_content_type = True
                break

        if has_vba_content_type:
            fname = (self.struct.filename or "").lower()
            non_macro_exts = (".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx", ".ppsx")
            if any(fname.endswith(ext) for ext in non_macro_exts):
                self.reports["content_type_mismatch"] = Report(
                    f"VBA/macro content type found in non-macro extension ({fname}). "
                    "File may have been renamed to bypass security controls.",
                    severity=Severity.CRITICAL,
                )

        # Check for DOCTYPE/entity declarations (XML bomb indicators)
        if "<!DOCTYPE" in raw or "<!ENTITY" in raw:
            self.reports["content_types_xxe"] = Report(
                "DOCTYPE or ENTITY declaration in [Content_Types].xml — possible XXE or XML bomb",
                severity=Severity.CRITICAL,
            )

        # --- Content_Types cross-validation ---
        ct_ns = root.tag.split("}")[0] + "}" if "}" in root.tag else ""
        override_parts = {}  # PartName -> list of ContentTypes
        default_exts = set()

        for elem in root:
            tag = elem.tag.replace(ct_ns, "")
            if tag == "Override":
                pn = elem.get("PartName", "")
                ct = elem.get("ContentType", "")
                override_parts.setdefault(pn, []).append(ct)
            elif tag == "Default":
                ext = elem.get("Extension", "").lower()
                if ext:
                    default_exts.add(ext)

        # 2a — Phantom parts: Override for PartNames not in ZIP
        phantoms = [
            pn for pn in override_parts
            if pn.lstrip("/") not in self._namelist
        ]
        if phantoms:
            self.reports["phantom_content_parts"] = Report(
                f"Content_Types declares parts not in archive: "
                f"{', '.join(phantoms[:10])}",
                severity=Severity.MEDIUM,
            )

        # 2b — Undeclared parts: ZIP entries with no matching declaration
        override_normalized = {pn.lstrip("/") for pn in override_parts}
        skip_patterns = (".rels", "[Content_Types].xml")
        undeclared = []
        for name in self._namelist:
            if name.endswith("/"):
                continue
            if any(name.endswith(sp) for sp in skip_patterns):
                continue
            if name == "[Content_Types].xml":
                continue
            if name in override_normalized:
                continue
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext and ext in default_exts:
                continue
            undeclared.append(name)
        if undeclared:
            self.reports["undeclared_parts"] = Report(
                f"ZIP entries with no Content_Types declaration: "
                f"{', '.join(undeclared[:10])}",
                severity=Severity.MEDIUM,
            )

        # 2c — Conflicting overrides: same PartName, different ContentTypes
        conflicts = {
            pn: cts for pn, cts in override_parts.items()
            if len(set(cts)) > 1
        }
        if conflicts:
            details = "; ".join(
                f"{pn}: {', '.join(cts)}" for pn, cts in conflicts.items()
            )
            self.reports["content_type_conflict"] = Report(
                f"Conflicting Content_Type overrides: {details}",
                severity=Severity.HIGH,
            )

        # 2d — Non-standard content types
        _KNOWN_CT_PREFIXES = (
            "application/vnd.openxmlformats-",
            "application/vnd.ms-",
            "application/xml",
            "application/zip",
            "application/octet-stream",
            "image/",
            "audio/",
            "video/",
            "text/",
        )
        unusual = []
        for pn, cts in override_parts.items():
            for ct in cts:
                if not any(ct.startswith(p) for p in _KNOWN_CT_PREFIXES):
                    unusual.append(f"{pn}: {ct}")
        if unusual:
            self.reports["unusual_content_type"] = Report(
                f"Non-standard content types: {'; '.join(unusual[:10])}",
                severity=Severity.LOW,
            )

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
        all_rel_types = set()  # Collect all Type URIs for nonstandard check

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
                if rel_type:
                    all_rel_types.add(rel_type)

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
                    target_lower = target.lower()

                    if "attachedTemplate" in rel_type:
                        self.reports[key] = Report(
                            f"Remote Template Injection detected. Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif target_lower.startswith("mhtml:"):
                        self.reports[key] = Report(
                            f"MHTML scheme in external reference — possible CVE-2021-40444 vector. "
                            f"Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif target_lower.startswith("ms-msdt:"):
                        self.reports[key] = Report(
                            f"ms-msdt: protocol handler — Follina exploit (CVE-2022-30190). "
                            f"Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif target.startswith("file://") or target.startswith("\\\\"):
                        self.reports[key] = Report(
                            f"Potential NTLM hash leak via file/UNC path. Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif "altChunk" in rel_type:
                        self.reports[key] = Report(
                            f"External altChunk can import external content. Target: {target}",
                            severity=Severity.HIGH,
                        )
                    elif "oleObject" in rel_type:
                        self.reports[key] = Report(
                            f"External OLE object link (possible CVE-2017-0199). Target: {target}",
                            severity=Severity.CRITICAL,
                        )
                    elif rel_type_suffix in ("frame", "subDocument"):
                        self.reports[key] = Report(
                            f"External {rel_type_suffix} — can load remote content. Target: {target}",
                            severity=Severity.HIGH,
                        )
                    else:
                        self.reports[key] = Report(
                            f"External link of type '{rel_type_suffix}'. Target: {target}",
                            severity=Severity.HIGH,
                        )

        # 3a — Dangling references: internal targets not in the ZIP
        dangling = [
            t for t in self._referenced_targets
            if t not in self._namelist and t.lstrip("/") not in self._namelist
        ]
        if dangling:
            self.reports["dangling_references"] = Report(
                f"Relationship targets not found in archive: "
                f"{', '.join(dangling[:10])}",
                severity=Severity.MEDIUM,
            )

        # 3b — Non-standard relationship types
        _KNOWN_REL_PREFIXES = (
            "http://schemas.openxmlformats.org/",
            "http://schemas.microsoft.com/",
            "http://purl.oclc.org/",
        )
        nonstandard = {
            rt for rt in all_rel_types
            if not any(rt.startswith(p) for p in _KNOWN_REL_PREFIXES)
        }
        if nonstandard:
            self.reports["nonstandard_rel_type"] = Report(
                f"Non-standard relationship types: {'; '.join(sorted(nonstandard)[:10])}",
                severity=Severity.LOW,
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

            # Line-based scans: DDE, XXE, XML bombs
            entity_count = 0
            for line_num, line in enumerate(content.splitlines(), 1):
                if "<!ENTITY" in line:
                    entity_count += 1
                    key = f"xxe_{xml_path}_{line_num}"
                    self.reports[key] = Report(
                        f"Potential XXE injection in {xml_path} line {line_num}: {line.strip()[:120]}",
                        severity=Severity.CRITICAL,
                    )
                if "<!DOCTYPE" in line:
                    key = f"doctype_{xml_path}_{line_num}"
                    self.reports[key] = Report(
                        f"DOCTYPE declaration in {xml_path} — not expected in OOXML",
                        severity=Severity.HIGH,
                    )
                for pattern, desc in suspicious_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        key = f"dde_{xml_path}_{line_num}"
                        self.reports[key] = Report(
                            f"Suspicious string ({desc}) in {xml_path} line {line_num}: {line.strip()[:120]}",
                            severity=Severity.CRITICAL,
                        )

            # XML bomb detection: multiple nested entity definitions
            if entity_count > 3:
                self.reports[f"xml_bomb_{xml_path}"] = Report(
                    f"Possible XML bomb (Billion Laughs) in {xml_path}: "
                    f"{entity_count} entity definitions found",
                    severity=Severity.CRITICAL,
                )

            # XML-parsed checks: suspicious tags, depth, mc:AlternateContent
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

                # 4a — Deep nesting detection
                depth = _measure_xml_depth(root)
                if depth > 50:
                    self.reports[f"deep_nesting_{xml_path}"] = Report(
                        f"Excessive XML nesting depth ({depth} levels) in {xml_path} "
                        f"— possible parser confusion attack",
                        severity=Severity.MEDIUM,
                    )

                # 4c — Excessive mc:AlternateContent
                mc_ns = "http://schemas.openxmlformats.org/markup-compatibility/2006"
                mc_count = len(root.findall(f".//{{{mc_ns}}}AlternateContent"))
                if mc_count > 10:
                    self.reports[f"mc_heavy_{xml_path}"] = Report(
                        f"{mc_count} mc:AlternateContent elements in {xml_path} "
                        f"— may hide content from parsers",
                        severity=Severity.MEDIUM,
                    )
            except ET.ParseError:
                pass

            # 4b — Large inline blobs (base64-like strings)
            # Skip customXml/ files — they have a dedicated lower-threshold check below
            if "customXml" not in xml_path:
                blob_match = re.search(r"[A-Za-z0-9+/=]{500,}", content)
                if blob_match:
                    excerpt = blob_match.group(0)[:75]
                    self.reports[f"large_blob_{xml_path}"] = Report(
                        f"Large base64-like blob ({len(blob_match.group(0))} chars) in {xml_path}. "
                        f"Excerpt: {excerpt}...",
                        severity=Severity.MEDIUM,
                    )

            # Custom XML payload detection (lower threshold for customXml/)
            if "customXml" in xml_path:
                match = re.search(r"[A-Za-z0-9+/=]{50,}", content)
                if match:
                    excerpt = match.group(0)[:75]
                    self.reports[f"customxml_payload_{xml_path}"] = Report(
                        f"Potentially encoded payload in {xml_path}. Excerpt: {excerpt}...",
                        severity=Severity.HIGH,
                    )

    # ------------------------------------------------------------------
    # VBA detection and decompilation
    # ------------------------------------------------------------------
    def _analyze_vba(self):
        vba_files = [f for f in self._namelist if "vbaProject.bin" in f]
        if not vba_files:
            return

        self.reports["vba_macros"] = Report(
            f"Document contains VBA macros ({', '.join(vba_files)}).",
            severity=Severity.CRITICAL,
        )

        if not _VBA_AVAILABLE:
            return

        # Extract and decompile each vbaProject.bin
        for vba_path in vba_files:
            try:
                vba_data = self._zip.read(vba_path)
                modules = extract_vba_from_ole_data(vba_data)

                for mod in modules:
                    code = mod["code"]
                    name = mod["name"]

                    # Report the decompiled source (truncated for display)
                    display_code = code[:2000] + "..." if len(code) > 2000 else code
                    self.reports[f"vba_source_{vba_path}_{name}"] = Report(
                        display_code,
                        short=f"VBA module: {name} ({len(code)} chars)",
                        label=f"VBA:{name}",
                    )

                    # Report suspicious patterns found in the code
                    for matched, category, sev_str in mod["findings"]:
                        sev = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.HIGH
                        key = f"vba_suspicious_{name}_{category}_{matched}"
                        self.reports[key] = Report(
                            f"VBA module '{name}': {category} — {matched}",
                            severity=sev,
                        )

                    # Emit decompiled source as child for IOC extraction
                    self.childitems.append(
                        self.generate_struct(
                            data=code.encode("utf-8"),
                            filename=f"vba_source_{name}.vba",
                            mime_type="text/plain",
                            index=len(self.childitems),
                        )
                    )
            except Exception as e:
                log.debug(f"VBA extraction failed for {vba_path}: {e}")

    # ------------------------------------------------------------------
    # Embedded object CLSID scan
    # ------------------------------------------------------------------
    def _check_embedded_clsids(self):
        """Scan files in /embeddings/ and /activeX/ for known dangerous CLSIDs."""
        from Analyzers.OLEOfficeAnalyzer import _DANGEROUS_CLSIDS, _CRITICAL_CLSIDS

        # Pre-compute binary representations of critical CLSIDs
        clsid_map = {}
        for clsid_str in _CRITICAL_CLSIDS:
            try:
                clsid_map[_clsid_str_to_bytes(clsid_str)] = (
                    clsid_str,
                    _DANGEROUS_CLSIDS.get(clsid_str, clsid_str),
                )
            except (ValueError, struct_mod.error):
                continue

        target_files = [
            f for f in self._namelist
            if ("/embeddings/" in f or "/activeX/" in f)
            and not f.endswith(".xml") and not f.endswith(".rels")
            and not f.endswith("/")
        ]

        for filepath in target_files:
            try:
                data = self._zip.read(filepath)
            except Exception:
                continue
            for clsid_bytes, (clsid_str, desc) in clsid_map.items():
                if clsid_bytes in data:
                    self.reports[f"embedded_clsid_{filepath}"] = Report(
                        f"Dangerous CLSID in {filepath}: {desc} ({clsid_str})",
                        severity=Severity.CRITICAL,
                    )
                    break  # one finding per file is enough

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
    # Hyperlink abuse — dangerous protocol handlers in links
    # ------------------------------------------------------------------
    def _detect_hyperlink_abuse(self):
        """Detect hyperlinks using dangerous protocol handlers."""
        _DANGEROUS_PROTOCOLS = {
            "ms-msdt:": "Follina exploit (CVE-2022-30190)",
            "ms-excel:": "Excel protocol handler abuse",
            "ms-word:": "Word protocol handler abuse",
            "mhtml:": "MHTML handler (CVE-2021-40444)",
            "cid:": "Content-ID reference",
        }
        w_ns = _WORD_NS["w"]

        for filepath in self._namelist:
            if not filepath.endswith(".xml"):
                continue
            try:
                raw = self._zip.read(filepath)
                root = ET.fromstring(raw)
            except Exception:
                continue

            # Word hyperlinks: <w:hyperlink r:id="..." /> and inline
            for hl in root.iter(f"{{{w_ns}}}hyperlink"):
                # Check w:anchor and r:id (the target is in .rels, already scanned)
                pass

            # Look for hyperlink targets directly in XML (PowerPoint, Excel)
            # Also detect file:// with ! (CVE-2024-21413 MonikerLink)
            content = raw.decode("utf-8", errors="ignore")
            # Match href="..." or Target="..." patterns containing protocols
            for m in re.finditer(r'(?:href|Target)\s*=\s*"([^"]+)"', content):
                url = m.group(1)
                url_lower = url.lower()

                for proto, desc in _DANGEROUS_PROTOCOLS.items():
                    if url_lower.startswith(proto):
                        key = f"hyperlink_abuse_{filepath}_{proto}"
                        self.reports[key] = Report(
                            f"Dangerous hyperlink protocol ({desc}): {url[:200]}",
                            severity=Severity.CRITICAL,
                        )
                        break

                # CVE-2024-21413: file:// with ! to bypass Protected View
                if url_lower.startswith("file://") and "!" in url:
                    self.reports[f"monikerlink_{filepath}"] = Report(
                        f"MonikerLink attack (CVE-2024-21413): file:// URL with '!' "
                        f"bypasses Protected View. URL: {url[:200]}",
                        severity=Severity.CRITICAL,
                    )

    # ------------------------------------------------------------------
    # SVG script detection in embedded media files
    # ------------------------------------------------------------------
    def _detect_svg_scripts(self):
        """Detect JavaScript in embedded SVG files (SVG smuggling)."""
        svg_files = [f for f in self._namelist if f.lower().endswith(".svg")]
        for svg_path in svg_files:
            try:
                content = self._zip.read(svg_path).decode("utf-8", errors="ignore")
                if re.search(r"<script[\s>]", content, re.IGNORECASE):
                    self.reports[f"svg_script_{svg_path}"] = Report(
                        f"SVG file contains <script> tag (SVG smuggling): {svg_path}",
                        severity=Severity.CRITICAL,
                    )
                # Also check for event handlers (onload, onclick, etc.)
                if re.search(r'\bon\w+\s*=', content, re.IGNORECASE):
                    self.reports[f"svg_event_{svg_path}"] = Report(
                        f"SVG file contains event handler attributes: {svg_path}",
                        severity=Severity.HIGH,
                    )
            except Exception:
                pass

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

            # VBA project binaries — only emit as child if we couldn't decompile
            if "vbaProject.bin" in filepath and not _VBA_AVAILABLE:
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

                    # Try to unwrap OLE Package objects from embeddings
                    if _OLEPACKAGE_AVAILABLE and "/embeddings/" in filepath:
                        pkg = parse_embedded_object(child_data)
                        if pkg and pkg.payload:
                            pkg_fname = pkg.filename or os.path.basename(filepath)
                            if pkg.is_dangerous:
                                self.reports[f"dangerous_embed_{filepath}"] = Report(
                                    f"Embedded object contains dangerous file: "
                                    f"{pkg.filename} (from {filepath})",
                                    severity=Severity.CRITICAL,
                                )
                            else:
                                self.reports[f"package_{filepath}"] = Report(
                                    f"OLE Package unwrapped: {pkg.filename} "
                                    f"({len(pkg.payload)} bytes, source: {pkg.source_path})",
                                    label=f"package:{filepath}",
                                )
                            # Emit the unwrapped payload instead of the raw OLE
                            child_struct = self.generate_struct(
                                filename=pkg_fname, data=pkg.payload, index=idx,
                            )
                            child_struct.parent = self.struct
                            self.childitems.append(child_struct)
                            idx += 1
                            continue

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
