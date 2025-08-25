from structure import Analyzer, Report
import xml.etree.ElementTree as ET
import re

class OfficeXMLAnalyzer(Analyzer):
    """
    Analyzes XML files found within Office documents (like DOCX) for
    suspicious content such as DDE, XXE, and encoded payloads.
    This analyzer is context-aware and will only run its checks if the
    XML file originates from a known Office container.
    """
    compatible_mime_types = ['application/xml', 'text/xml']
    description = "Office XML Content Analyzer"

    def analysis(self):
        super().analysis()

        # Context-aware check: Only run on XMLs from known Office containers.
        # This check is done by name to avoid circular import dependencies.
        if not self.struct.parent or not self.struct.parent.analyzer.__class__.__name__ in ['DocxAnalyzer']:
            return

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
