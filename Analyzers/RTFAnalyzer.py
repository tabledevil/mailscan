import logging
import re
import struct as struct_mod
from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")


class RTFAnalyzer(Analyzer):
    """Analyzer for Rich Text Format files.

    Detects embedded OLE objects, suspicious control words commonly used
    in exploits (e.g. CVE-2017-11882 Equation Editor, CVE-2017-0199),
    and obfuscation techniques.
    """

    compatible_mime_types = [
        "application/rtf",
        "text/rtf",
    ]
    description = "RTF Analyser"

    # RTF control words associated with exploit techniques
    SUSPICIOUS_CONTROL_WORDS = {
        r"\objdata": "OLE object data — may contain embedded executable or exploit payload",
        r"\objautlink": "OLE auto-link — can trigger automatic execution of linked object",
        r"\objupdate": "OLE auto-update — triggers automatic update of embedded object",
        r"\objocx": "OLE ActiveX control — may execute code via embedded ActiveX",
        r"\objhtml": "OLE HTML object — can load remote content",
        r"\object": "Embedded OLE object",
        r"\equation": "Equation Editor object — associated with CVE-2017-11882 exploit",
        r"\ddeauto": "DDE auto-execute — Dynamic Data Exchange automatic link",
        r"\dde": "DDE field — Dynamic Data Exchange link",
        r"\package": "OLE Package — can wrap arbitrary files including executables",
    }

    # Patterns indicating obfuscation
    OBFUSCATION_PATTERNS = [
        (re.compile(rb"\\bin\s*\d+", re.IGNORECASE), "Binary data blob (\\bin)"),
        (re.compile(rb"\\objdata\s+[0-9a-fA-F]{200,}"), "Large hex-encoded OLE object data"),
        (re.compile(rb"(?:\\[a-z]+\s*){50,}"), "Excessive control word sequence (possible obfuscation)"),
    ]

    # Known CLSID prefixes for dangerous OLE objects (hex-encoded, little-endian)
    DANGEROUS_CLSIDS = {
        "0002ce02": "Equation Editor 3.0 (CVE-2017-11882)",
        "00021401": "Windows Shell Link (.lnk)",
        "f20da720": "OLE Package object",
        "00020906": "Microsoft Word Document (embedded)",
    }

    def analysis(self):
        self.modules["parse_rtf"] = self._parse_rtf
        self.modules["detect_suspicious_words"] = self._detect_suspicious_control_words
        self.modules["detect_ole_objects"] = self._detect_ole_objects
        self.modules["detect_obfuscation"] = self._detect_obfuscation
        self.modules["extract_text"] = self._extract_text
        super().analysis()

    def _parse_rtf(self):
        data = self.struct.rawdata
        if not data or not data.lstrip().startswith(b"{\\rtf"):
            self.reports["format"] = Report(
                "File does not start with RTF header",
                severity=Severity.LOW,
            )
            return

        # Count nesting depth
        max_depth = 0
        depth = 0
        for byte in data:
            if byte == ord("{"):
                depth += 1
                max_depth = max(max_depth, depth)
            elif byte == ord("}"):
                depth -= 1

        self.info = f"RTF document, nesting depth {max_depth}"
        self.reports["nesting_depth"] = Report(
            str(max_depth), label="Nesting depth"
        )

        if max_depth > 100:
            self.reports["deep_nesting"] = Report(
                f"Unusually deep nesting ({max_depth} levels) — possible obfuscation",
                severity=Severity.MEDIUM,
            )

    def _detect_suspicious_control_words(self):
        data = self.struct.rawdata.lower()
        found = []

        for word, description in self.SUSPICIOUS_CONTROL_WORDS.items():
            pattern = word.encode("ascii").replace(b"\\", b"\\\\")
            escaped_word = re.escape(word.encode("ascii"))
            if re.search(escaped_word, data):
                found.append(f"{word}: {description}")

        if found:
            severity = Severity.HIGH if any(
                w in data for w in [b"\\objdata", b"\\ddeauto", b"\\equation", b"\\objautlink"]
            ) else Severity.MEDIUM

            self.reports["suspicious_control_words"] = Report(
                "\n".join(found),
                short=f"{len(found)} suspicious control word(s) detected",
                label="Suspicious RTF control words",
                severity=severity,
            )

    def _detect_ole_objects(self):
        """Scan for hex-encoded OLE object data and check CLSIDs."""
        data = self.struct.rawdata
        ole_pattern = re.compile(rb"\\objdata\s+([0-9a-fA-F\s]+)", re.DOTALL)
        matches = ole_pattern.findall(data)

        if not matches:
            return

        self.reports["ole_count"] = Report(
            f"{len(matches)} embedded OLE object(s)",
            label="OLE objects",
            severity=Severity.MEDIUM,
        )

        for i, hex_data in enumerate(matches):
            clean_hex = re.sub(rb"\s+", b"", hex_data)
            # Check for dangerous CLSIDs in the first bytes
            if len(clean_hex) >= 16:
                try:
                    raw_bytes = bytes.fromhex(clean_hex[:16].decode("ascii"))
                    clsid_prefix = raw_bytes[:4].hex()
                    if clsid_prefix in self.DANGEROUS_CLSIDS:
                        self.reports[f"ole_clsid_{i}"] = Report(
                            f"OLE object #{i+1} contains dangerous CLSID: "
                            f"{self.DANGEROUS_CLSIDS[clsid_prefix]}",
                            severity=Severity.CRITICAL,
                        )
                except (ValueError, UnicodeDecodeError):
                    pass

            # Extract embedded OLE as child for further analysis
            if len(clean_hex) > 32:
                try:
                    raw = bytes.fromhex(clean_hex.decode("ascii"))
                    self.childitems.append(
                        self.generate_struct(
                            data=raw,
                            filename=f"ole_object_{i}.bin",
                        )
                    )
                except (ValueError, UnicodeDecodeError):
                    pass

    def _detect_obfuscation(self):
        data = self.struct.rawdata
        findings = []

        for pattern, description in self.OBFUSCATION_PATTERNS:
            if pattern.search(data):
                findings.append(description)

        # Check for hex-encoded content outside of OLE objects
        # (common obfuscation technique to hide URLs/commands)
        hex_runs = re.findall(rb"(?:(?:\\\'[0-9a-fA-F]{2}){10,})", data)
        if hex_runs:
            findings.append(
                f"{len(hex_runs)} hex-escaped string(s) detected "
                f"(possible obfuscated content)"
            )

        if findings:
            self.reports["obfuscation"] = Report(
                "\n".join(findings),
                short=f"{len(findings)} obfuscation indicator(s)",
                label="Obfuscation indicators",
                severity=Severity.MEDIUM,
            )

    def _extract_text(self):
        """Basic RTF-to-text extraction for IOC analysis."""
        data = self.struct.rawdata
        # Strip RTF control words and groups to get plain text
        text = data
        # Remove hex-escaped characters
        text = re.sub(rb"\\'([0-9a-fA-F]{2})", lambda m: bytes([int(m.group(1), 16)]), text)
        # Remove control words
        text = re.sub(rb"\\[a-z]+\d*\s?", b" ", text)
        # Remove braces
        text = re.sub(rb"[{}]", b"", text)
        # Clean up whitespace
        text = re.sub(rb"\s+", b" ", text).strip()

        if len(text) > 10:
            try:
                decoded = text.decode("utf-8", errors="replace")
                # Only pass to child if there's meaningful text content
                printable_ratio = sum(1 for c in decoded if c.isprintable() or c.isspace()) / max(len(decoded), 1)
                if printable_ratio > 0.7:
                    self.childitems.append(
                        self.generate_struct(
                            data=decoded.encode("utf-8"),
                            filename="extracted_text.txt",
                            mime_type="text/plain",
                        )
                    )
            except Exception:
                pass
