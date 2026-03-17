"""
OLE Office Document Analyzer (legacy binary formats).

Handles .doc, .xls, .ppt and other OLE2/Compound File Binary Format
documents.  Performs structural, VBA macro, embedded object, CLSID,
metadata, document type identification, and IOC analysis in a single pass.

Requires the ``olefile`` library (pip install olefile).
"""

import io
import logging
import os
import re
import struct as struct_mod

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

# Try to import IOC extractor
try:
    from Utils.ioc_extractor import extract_iocs

    _IOC_AVAILABLE = True
except ImportError:
    _IOC_AVAILABLE = False

# OLE2 file magic bytes
_OLE_MAGIC = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"

# Well-known dangerous CLSIDs (lowercase, with dashes)
_DANGEROUS_CLSIDS = {
    "00020906-0000-0000-c000-000000000046": "Microsoft Word Document",
    "00020900-0000-0000-c000-000000000046": "Microsoft Word 6.0-7.0 Document",
    "00020820-0000-0000-c000-000000000046": "Microsoft Excel Worksheet",
    "00020810-0000-0000-c000-000000000046": "Microsoft Excel 5.0/95 Worksheet",
    "64818d10-4f9b-11cf-86ea-00aa00b929e8": "Microsoft PowerPoint Presentation",
    "0002ce02-0000-0000-c000-000000000046": "Equation Editor 3.0 (CVE-2017-11882)",
    "0003000c-0000-0000-c000-000000000046": "OLE Package object",
    "f20da720-c02f-11ce-927b-0800095ae340": "OLE Package (alternate)",
    "00021401-0000-0000-c000-000000000046": "Windows Shell Link (.lnk)",
    "d5cdd505-2e9c-101b-9397-08002b2cf9ae": "DocumentSummaryInformation",
}

# CLSIDs that identify document type
_DOC_TYPE_CLSIDS = {
    "00020906-0000-0000-c000-000000000046": "Word",
    "00020900-0000-0000-c000-000000000046": "Word",
    "00020820-0000-0000-c000-000000000046": "Excel",
    "00020810-0000-0000-c000-000000000046": "Excel",
    "64818d10-4f9b-11cf-86ea-00aa00b929e8": "PowerPoint",
}

# Streams that identify document type
_DOC_TYPE_STREAMS = {
    "worddocument": "Word",
    "1table": "Word",
    "0table": "Word",
    "workbook": "Excel",
    "book": "Excel",
    "powerpointdocument": "PowerPoint",
}

# Stream names associated with VBA macros
_VBA_STREAM_NAMES = {"vba", "_vba_project", "vbaproject.otm"}

# Known macro-related stream path components
_VBA_PATH_PARTS = {"VBA", "Macros", "_VBA_PROJECT_CUR"}

# Suspicious stream names (case-insensitive matching) -> (description, severity)
_SUSPICIOUS_STREAMS = {
    "\x01ole": ("OLE native data stream", Severity.INFO),
    "\x01compobj": ("Compound object identification", Severity.INFO),
    "\x03objinfo": ("Object information stream", Severity.INFO),
    "equationnative": ("Equation Editor native data — possible exploit vector", Severity.HIGH),
    "powerpointdocument": ("PowerPoint document stream", Severity.INFO),
    "worddocument": ("Word document stream", Severity.INFO),
    "workbook": ("Excel workbook stream", Severity.INFO),
    "book": ("Excel 5.0/95 workbook stream", Severity.INFO),
}

# Excel BIFF record IDs
_BIFF_FILEPASS = 0x002F
_BIFF_RECORD_HEADER_SIZE = 4


class OLEOfficeAnalyzer(Analyzer):
    """
    Analyzer for legacy OLE2 Office documents (.doc, .xls, .ppt).

    Performs:
    - Document type identification (Word/Excel/PowerPoint)
    - Structural analysis (stream listing, storage tree)
    - VBA macro detection and extraction
    - Embedded OLE object detection
    - CLSID analysis for dangerous object types
    - Metadata extraction
    - Encrypted document detection
    - IOC extraction from document text
    """

    compatible_mime_types = [
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/x-ole-storage",
        "application/CDFV2",
        "application/CDFV2-corrupt",
    ]

    description = "OLE Office Document Analyzer (.doc/.xls/.ppt)"
    pip_dependencies = ["olefile"]

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Detect OLE2 files by magic bytes when MIME is ambiguous."""
        if not struct.rawdata or len(struct.rawdata) < 8:
            return False
        return struct.rawdata[:8] == _OLE_MAGIC

    def analysis(self):
        super().analysis()

        try:
            import olefile
        except ImportError:
            self.reports["error"] = Report(
                "olefile library not installed. Install with: pip install olefile",
                severity=Severity.INFO,
            )
            return

        try:
            self._ole = olefile.OleFileIO(io.BytesIO(self.struct.rawdata))
        except Exception as e:
            self.reports["error"] = Report(
                f"Failed to parse OLE file: {e}",
                severity=Severity.HIGH,
            )
            return

        try:
            self._streams = self._ole.listdir(streams=True, storages=False)
            self._all_entries = self._ole.listdir(streams=True, storages=True)
            stream_count = len(self._streams)

            doc_type = self._identify_document_type()
            self.info = f"OLE {doc_type} document — {stream_count} stream(s)"

            self._analyze_structure()
            self._analyze_clsids()
            self._analyze_vba()
            self._analyze_metadata()
            self._analyze_embedded_objects()
            self._detect_encryption()
            self._extract_text_and_iocs()
        finally:
            self._ole.close()

    # ------------------------------------------------------------------
    # Document type identification
    # ------------------------------------------------------------------
    def _identify_document_type(self):
        """Determine if this is Word, Excel, or PowerPoint."""
        # Check root CLSID first
        try:
            root_clsid = self._ole.root.clsid
            if root_clsid:
                doc_type = _DOC_TYPE_CLSIDS.get(root_clsid.lower())
                if doc_type:
                    self.reports["doc_type"] = Report(
                        doc_type, label="Document type",
                    )
                    return doc_type
        except Exception:
            pass

        # Fall back to stream-based identification
        for parts in self._streams:
            name_lower = parts[-1].lower() if parts else ""
            doc_type = _DOC_TYPE_STREAMS.get(name_lower)
            if doc_type:
                self.reports["doc_type"] = Report(
                    doc_type, label="Document type",
                )
                return doc_type

        return "unknown"

    # ------------------------------------------------------------------
    # Structural analysis — list streams, flag suspicious ones
    # ------------------------------------------------------------------
    def _analyze_structure(self):
        stream_paths = ["/".join(parts) for parts in self._streams]
        self.reports["streams"] = Report(
            "\n".join(stream_paths) if stream_paths else "(empty)",
            label="OLE streams",
        )

        # Flag suspicious streams
        for parts in self._streams:
            full_path = "/".join(parts)
            name_lower = parts[-1].lower() if parts else ""

            for suspect, (description, sev) in _SUSPICIOUS_STREAMS.items():
                if suspect in name_lower:
                    self.reports[f"stream_{full_path}"] = Report(
                        f"Contains {description}: {full_path}",
                        label=f"stream:{full_path}",
                        severity=sev,
                    )

    # ------------------------------------------------------------------
    # CLSID analysis — check root and storage CLSIDs for dangerous types
    # ------------------------------------------------------------------
    def _analyze_clsids(self):
        # Check root CLSID
        try:
            root_clsid = self._ole.root.clsid
            if root_clsid and root_clsid != "00000000-0000-0000-0000-000000000000":
                clsid_lower = root_clsid.lower()
                desc = _DANGEROUS_CLSIDS.get(clsid_lower, "")
                label = f"Root CLSID: {root_clsid}"
                if desc:
                    label += f" ({desc})"
                self.reports["root_clsid"] = Report(label)

                if clsid_lower in _DANGEROUS_CLSIDS and "equation" in _DANGEROUS_CLSIDS[clsid_lower].lower():
                    self.reports["equation_editor"] = Report(
                        "Equation Editor CLSID detected — associated with CVE-2017-11882 exploit",
                        severity=Severity.CRITICAL,
                    )
        except Exception:
            pass

        # Check storage CLSIDs
        for parts in self._all_entries:
            try:
                path = "/".join(parts)
                clsid = self._ole.getclsid(path)
                if clsid and clsid != "00000000-0000-0000-0000-000000000000":
                    clsid_lower = clsid.lower()
                    if clsid_lower in _DANGEROUS_CLSIDS:
                        desc = _DANGEROUS_CLSIDS[clsid_lower]
                        sev = Severity.CRITICAL if "equation" in desc.lower() or "shell link" in desc.lower() else Severity.MEDIUM
                        self.reports[f"clsid_{path}"] = Report(
                            f"Storage '{path}' has CLSID {clsid} ({desc})",
                            severity=sev,
                        )
            except Exception:
                pass

    # ------------------------------------------------------------------
    # VBA macro detection
    # ------------------------------------------------------------------
    def _analyze_vba(self):
        has_vba = False

        for parts in self._streams:
            # Check if any path component indicates VBA
            for part in parts:
                if part.lower() in _VBA_STREAM_NAMES or part in _VBA_PATH_PARTS:
                    has_vba = True
                    break

            # Also check for streams named like VBA modules
            full_path = "/".join(parts)
            if full_path.lower().endswith("vbaproject.bin"):
                has_vba = True

        if has_vba:
            self.reports["vba_macros"] = Report(
                "Document contains VBA macros",
                severity=Severity.CRITICAL,
            )

            # Try to extract VBA stream data as children for deeper analysis
            for parts in self._streams:
                full_path = "/".join(parts)
                # Extract actual VBA code streams (not dir or project metadata)
                is_vba_container = any(p in _VBA_PATH_PARTS or p.lower() in _VBA_STREAM_NAMES for p in parts)
                is_metadata = parts[-1].lower() in {"dir", "project", "projectwm", "_vba_project"}
                if is_vba_container and not is_metadata:
                    try:
                        data = self._ole.openstream(parts).read()
                        if len(data) > 0:
                            self.childitems.append(
                                self.generate_struct(
                                    data=data,
                                    filename=full_path.replace("/", "_"),
                                    index=len(self.childitems),
                                )
                            )
                    except Exception as e:
                        log.debug(f"Could not extract VBA stream {full_path}: {e}")

    # ------------------------------------------------------------------
    # Metadata extraction
    # ------------------------------------------------------------------
    def _analyze_metadata(self):
        try:
            meta = self._ole.get_metadata()
        except Exception:
            return

        findings = []

        # Extract interesting metadata fields
        fields = {
            "author": meta.author,
            "last_saved_by": meta.last_saved_by,
            "creating_application": meta.creating_application,
            "company": meta.company,
            "title": meta.title,
            "subject": meta.subject,
            "comments": meta.comments,
        }

        for name, value in fields.items():
            if value:
                # Decode if bytes
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="replace")
                    except Exception:
                        value = repr(value)
                findings.append(f"{name}: {value}")

        # Check timestamps
        for ts_name in ("create_time", "last_saved_time"):
            ts = getattr(meta, ts_name, None)
            if ts:
                findings.append(f"{ts_name}: {ts}")

        if findings:
            self.reports["metadata"] = Report(
                "\n".join(findings),
                label="Document metadata",
            )

        # Flag suspicious metadata (e.g., template names)
        if meta.template:
            template = meta.template
            if isinstance(template, bytes):
                template = template.decode("utf-8", errors="replace")
            if template.lower().startswith("http") or template.lower().startswith("\\\\"):
                self.reports["remote_template"] = Report(
                    f"Document references remote template: {template}",
                    severity=Severity.CRITICAL,
                )
            elif template.lower() != "normal.dotm" and template.lower() != "normal":
                self.reports["template"] = Report(
                    f"Document template: {template}",
                    label="template",
                )

    # ------------------------------------------------------------------
    # Embedded OLE objects — extract for child analysis
    # ------------------------------------------------------------------
    def _analyze_embedded_objects(self):
        extracted_paths = set()
        embedded_count = 0

        for parts in self._streams:
            full_path = "/".join(parts)
            name_lower = parts[-1].lower() if parts else ""

            # Look for embedded object streams — with correct precedence
            is_embedding = (
                name_lower.startswith("\x01ole")
                or name_lower == "package"
                or (name_lower.startswith("ole") and name_lower not in {"olestream", "oleprops"})
            )

            if is_embedding and full_path not in extracted_paths:
                try:
                    data = self._ole.openstream(parts).read()
                    if len(data) > 0:
                        embedded_count += 1
                        extracted_paths.add(full_path)
                        self.childitems.append(
                            self.generate_struct(
                                data=data,
                                filename=f"embedded_{full_path.replace('/', '_')}",
                                index=len(self.childitems),
                            )
                        )
                except Exception as e:
                    log.debug(f"Could not extract embedded object {full_path}: {e}")

        # Extract streams under ObjectPool storage
        for parts in self._all_entries:
            full_path = "/".join(parts)
            if "objectpool" in full_path.lower() and self._ole.get_type(parts) == 1:
                # It's a storage — extract its child streams
                try:
                    for stream_parts in self._streams:
                        child_path = "/".join(stream_parts)
                        if child_path in extracted_paths:
                            continue
                        if len(stream_parts) > len(parts) and stream_parts[:len(parts)] == parts:
                            data = self._ole.openstream(stream_parts).read()
                            if len(data) > 0:
                                embedded_count += 1
                                extracted_paths.add(child_path)
                                self.childitems.append(
                                    self.generate_struct(
                                        data=data,
                                        filename=f"objpool_{child_path.replace('/', '_')}",
                                        index=len(self.childitems),
                                    )
                                )
                except Exception as e:
                    log.debug(f"Could not extract ObjectPool contents: {e}")

        if embedded_count > 0:
            self.reports["embedded_objects"] = Report(
                f"{embedded_count} embedded OLE object(s) extracted for analysis",
                severity=Severity.HIGH,
            )

    # ------------------------------------------------------------------
    # Encryption detection
    # ------------------------------------------------------------------
    def _detect_encryption(self):
        # Check for EncryptedPackage stream (Office encryption)
        for parts in self._streams:
            name = parts[-1].lower() if parts else ""
            if name == "encryptedpackage" or name == "encryptioninfo":
                self.reports["encrypted"] = Report(
                    "Document is encrypted (EncryptedPackage detected)",
                    severity=Severity.MEDIUM,
                )
                return

        # Check for FilePass BIFF record in Excel workbooks
        for parts in self._streams:
            full_path = "/".join(parts).lower()
            if "workbook" in full_path or full_path.endswith("/book"):
                try:
                    data = self._ole.openstream(parts).read()
                    if self._has_biff_filepass(data):
                        self.reports["excel_password"] = Report(
                            "Excel workbook is password-protected (FilePass BIFF record found)",
                            severity=Severity.MEDIUM,
                        )
                except Exception:
                    pass

    @staticmethod
    def _has_biff_filepass(data):
        """Scan BIFF records for a FilePass (0x002F) record."""
        offset = 0
        while offset + _BIFF_RECORD_HEADER_SIZE <= len(data):
            try:
                record_id, record_len = struct_mod.unpack_from("<HH", data, offset)
            except struct_mod.error:
                break
            if record_id == _BIFF_FILEPASS:
                return True
            # Move to next record
            offset += _BIFF_RECORD_HEADER_SIZE + record_len
            # Safety: if record_len is 0 we'd loop forever
            if record_len == 0 and record_id == 0:
                break
        return False

    # ------------------------------------------------------------------
    # Text extraction and IOC scanning
    # ------------------------------------------------------------------
    def _extract_text_and_iocs(self):
        """Extract readable text from document streams and scan for IOCs."""
        if not _IOC_AVAILABLE:
            return

        text_parts = []

        for parts in self._streams:
            full_path = "/".join(parts)
            name_lower = parts[-1].lower() if parts else ""

            # Try to extract text from known text-bearing streams
            # Word: WordDocument stream contains binary but text can be in
            #        the Data or 1Table/0Table streams (complex to parse)
            # Instead, look for plain text in any stream that might have it
            if name_lower in {"worddocument", "powerpointdocument"}:
                try:
                    data = self._ole.openstream(parts).read()
                    # Extract printable ASCII/UTF-16 strings
                    text_parts.extend(self._extract_strings(data))
                except Exception:
                    pass

        if not text_parts:
            return

        full_text = "\n".join(text_parts)
        if not full_text.strip():
            return

        try:
            iocs = extract_iocs(full_text)
            if iocs.has_findings:
                parts_summary = iocs.summary_parts()
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
                    short=", ".join(parts_summary),
                    label="iocs",
                    severity=Severity.MEDIUM if (iocs.urls or iocs.ipv4) else Severity.INFO,
                )
        except Exception as e:
            log.debug(f"IOC extraction failed: {e}")

    @staticmethod
    def _extract_strings(data, min_length=6):
        """Extract printable ASCII and UTF-16LE strings from binary data."""
        strings = []

        # ASCII strings
        ascii_pattern = re.compile(rb"[\x20-\x7E]{%d,}" % min_length)
        for match in ascii_pattern.finditer(data):
            try:
                strings.append(match.group().decode("ascii"))
            except Exception:
                pass

        # UTF-16LE strings (common in OLE documents)
        utf16_pattern = re.compile(
            rb"(?:[\x20-\x7E]\x00){%d,}" % min_length
        )
        for match in utf16_pattern.finditer(data):
            try:
                decoded = match.group().decode("utf-16-le")
                if decoded not in strings:  # avoid duplicates
                    strings.append(decoded)
            except Exception:
                pass

        return strings
