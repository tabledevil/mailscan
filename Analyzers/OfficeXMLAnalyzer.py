from structure import Analyzer, Report, Severity
import base64
import binascii
import xml.etree.ElementTree as ET
import re

# Standalone ("flat") Office XML documents: Word 2003 XML (WordprocessingML
# 2003) and Flat OPC (Office 2007+ saved as a single XML).  Word opens both
# even when renamed to .doc, and both can carry binary parts (images, OLE
# objects, ``editdata.mso`` = ActiveMime with VBA macros).
_FLAT_MARKERS = (b'progid="word.document"', b'progid="excel.sheet"',
                 b'progid="powerpoint.show"',
                 b"schemas.microsoft.com/office/word/2003/wordml",
                 b"schemas.microsoft.com/office/2006/xmlpackage")
_BINDATA_RE = re.compile(rb'<w:binData\b[^>]*?w:name="([^"]*)"[^>]*>(.*?)</w:binData>', re.S)
_PKG_PART_RE = re.compile(
    rb'<pkg:part\b[^>]*?pkg:name="([^"]*)"[^>]*>\s*<pkg:binaryData>(.*?)</pkg:binaryData>', re.S)

def unpack_activemime(blob: bytes):
    """ActiveMime (``editdata.mso``): a small header, then a zlib stream that
    holds an OLE file with the VBA project.  Returns the OLE bytes or None."""
    import zlib
    if not blob.startswith(b"ActiveMime"):
        return None
    for off in (0x32, *[m.start() for m in re.finditer(rb"\x78[\x01\x5e\x9c\xda]", blob[:512])]):
        try:
            out = zlib.decompress(blob[off:])
        except zlib.error:
            continue
        if out:
            return out
    return None


class OfficeXMLAnalyzer(Analyzer):
    """
    Analyzes XML files found within Office documents (like DOCX) for
    suspicious content such as DDE, XXE, and encoded payloads.
    This analyzer is context-aware and will only run its checks if the
    XML file originates from a known Office container.
    """
    compatible_mime_types = ['application/xml', 'text/xml']
    description = "Office XML Content Analyzer"
    specificity = 25

    @staticmethod
    def is_flat_office_xml(data: bytes) -> bool:
        head = (data or b"")[:4096].lower()
        return any(m in head for m in _FLAT_MARKERS)

    def _flat_document(self):
        """Report a standalone Office XML document and extract its binary
        parts as children, so macros/OLE objects inside get analyzed."""
        data = self.struct.rawdata
        kind = ("Flat OPC (Office 2007+ single-file XML)"
                if b"office/2006/xmlpackage" in data[:4096].lower()
                else "Word 2003 XML (WordprocessingML)")
        parts = [(n, b) for n, b in _BINDATA_RE.findall(data)]
        parts += [(n, b) for n, b in _PKG_PART_RE.findall(data)]
        names = []
        for idx, (name, b64) in enumerate(parts):
            try:
                blob = base64.b64decode(re.sub(rb"\s+", b"", b64), validate=False)
            except (binascii.Error, ValueError):
                continue
            fname = name.decode("utf-8", "replace").rsplit("/", 1)[-1] or f"part_{idx}.bin"
            names.append(name.decode("utf-8", "replace"))
            inner = unpack_activemime(blob)
            if inner is not None:   # editdata.mso → the OLE vbaProject inside
                blob, fname = inner, fname + ".ole"
            self.childitems.append(self.generate_struct(
                data=blob, filename=fname, index=idx, parent=self.struct))
        macro = [n for n in names if n.lower().endswith((".mso", "vbaproject.bin"))]
        self.info = f"{kind} — {len(names)} embedded binary part(s)"
        self.reports["flat_office_xml"] = Report(
            f"{kind}; embedded binary parts: {', '.join(names) or 'none'}",
            short=kind, label="flat_office_xml",
            severity=Severity.MEDIUM if macro else Severity.INFO, verbosity=0,
            data={"kind": kind, "parts": names},
        )
        if macro:
            self.reports["flat_office_xml_macros"] = Report(
                f"Macro container embedded in XML document: {', '.join(macro)}",
                short="macros in flat XML", label="macros", severity=Severity.HIGH,
                verbosity=0, data={"parts": macro},
            )

    def analysis(self):
        super().analysis()

        flat = self.is_flat_office_xml(self.struct.rawdata)
        if flat:
            self._flat_document()
        # Context-aware check: Only run on XMLs from known Office containers
        # (or standalone Office XML documents).  By name to avoid circular imports.
        elif not self.struct.parent or not self.struct.parent.analyzer.__class__.__name__ in ['DocxAnalyzer', 'OfficeDocumentAnalyzer']:
            return
        else:
            self.info = "Scanning Office XML for suspicious content."

        try:
            content = self.struct.rawdata.decode('utf-8', errors='ignore')
        except Exception as e:
            self.reports['decode_error'] = Report(f"Could not decode XML content: {e}", rank=1)
            return

        # --- High-severity string/line-based scans (DDE, XXE) ---
        suspicious_strings = {r'\bDDE\b': 'DDE field', r'\bDDEAUTO\b': 'DDE Auto-execution'}
        for line_num, line in enumerate(content.splitlines(), 1):
            if '<!ENTITY' in line:
                report = Report(f"CRITICAL: Potential XXE injection found on line {line_num}: {line.strip()}", rank=2)
                self.reports[f'xxe_{line_num}'] = report
            for pattern, desc in suspicious_strings.items():
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    report = Report(f"CRITICAL: Suspicious string '{match.group(0)}' ({desc}) found on line {line_num}: {line.strip()}", rank=2)
                    self.reports[f'dde_{line_num}'] = report

        # --- Scans that require XML parsing (suspicious tags) ---
        try:
            # Use the raw bytes for parsing to handle XML encoding declarations correctly
            root = ET.fromstring(self.struct.rawdata)
            ns = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'}
            suspicious_tags = {'w:subDoc': 'Sub-document inclusion', 'w:control': 'ActiveX Control'}

            for tag, desc in suspicious_tags.items():
                if root.findall(f'.//{tag}', ns):
                    self.reports[f'suspicious_tag_{tag}'] = Report(f"WARNING: Suspicious tag '{tag}' ({desc}) found.", rank=1)
        except ET.ParseError:
            # Errors are common, especially with malformed docs. Fail gracefully.
            pass

        # --- Scan for payloads in custom XML parts ---
        if self.struct.filename and 'customXml' in self.struct.filename:
            # Look for long strings of Base64-like characters (e.g., > 50 chars)
            match = re.search(r'[A-Za-z0-9+/=]{50,}', content)
            if match:
                excerpt = (match.group(0)[:75] + '...') if len(match.group(0)) > 75 else match.group(0)
                report = Report(f"WARNING: Found potentially encoded payload string in customXml. Excerpt: {excerpt}", rank=1)
                self.reports['customxml_payload'] = report
