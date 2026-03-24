"""JavaScript/JScript static analysis analyzer.

Detects download cradles, WScript/ActiveX execution chains, obfuscation
techniques, and produces triage-ready severity ratings via pure-Python
static analysis — no JS execution.
"""

import logging
import os
import re
from structure import Analyzer, Report, Severity
from Utils.js_analysis import (
    decode_js,
    strip_comments,
    extract_string_literals,
    unescape_hex,
    unescape_unicode,
    resolve_from_char_code,
    extract_base64_blobs,
    fold_string_concat,
    compute_metrics,
    obfuscation_score,
    detect_threat_patterns,
    detect_kill_chain,
    detect_api_fragmentation,
    detect_jse,
    detect_library,
)

log = logging.getLogger("matt")

try:
    import jsbeautifier
    _JSBEAUTIFIER_AVAILABLE = True
except ImportError:
    _JSBEAUTIFIER_AVAILABLE = False


class ScriptAnalyzer(Analyzer):
    compatible_mime_types = [
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "text/x-javascript",
        "text/jscript",
        "application/ecmascript",
        "text/ecmascript",
    ]
    description = "JavaScript/Script Analyser"
    specificity = 20
    optional_pip_dependencies = [("jsbeautifier", "jsbeautifier")]
    optional_system_dependencies = ["box-js"]
    extra = "js"

    # Extensions recognized for content probing
    _JS_EXTENSIONS = {".js", ".jse", ".mjs", ".cjs"}

    # Structural signatures for content-based detection
    _JS_SIGNATURES = [
        re.compile(r"\bfunction\s"),
        re.compile(r"\bvar\s"),
        re.compile(r"\blet\s"),
        re.compile(r"\bconst\s"),
        re.compile(r"\bWScript\."),
        re.compile(r"\bActiveXObject\b"),
        re.compile(r"^#!/usr/bin/env\s+node", re.MULTILINE),
        re.compile(r"\brequire\s*\("),
        re.compile(r"\bmodule\.exports\b"),
        re.compile(r"=>"),
    ]

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Content probe for application/octet-stream or text/plain."""
        if struct.mime_type not in ("application/octet-stream", "text/plain"):
            return False

        # Check filename extension
        filename = getattr(struct, "filename", "") or ""
        _, ext = os.path.splitext(filename)
        has_js_ext = ext.lower() in cls._JS_EXTENSIONS

        # Check content for JS structural signatures
        try:
            text = struct.rawdata[:4096].decode("utf-8", errors="replace")
        except Exception:
            return False

        hits = sum(1 for sig in cls._JS_SIGNATURES if sig.search(text))

        # Extension match + any content hit, or 2+ content hits without ext
        if has_js_ext and hits >= 1:
            return True
        if hits >= 2:
            return True

        # JScript.Encode marker
        if b"#@~^" in struct.rawdata[:1024]:
            return True

        return False

    def analysis(self):
        self.modules["identify"] = self._identify
        self.modules["compute_metrics"] = self._compute_metrics
        self.modules["detect_threats"] = self._detect_threats
        self.modules["extract_strings"] = self._extract_strings
        self.modules["extract_base64"] = self._extract_base64
        self.modules["beautify"] = self._beautify
        self.modules["detect_jse"] = self._detect_jse
        self.modules["deobfuscate"] = self._deobfuscate
        self.modules["dynamic_analysis"] = self._dynamic
        super().analysis()

    def _identify(self):
        """Detect script type, encoding."""
        raw = self.struct.rawdata
        self._source, self._encoding = decode_js(raw)
        self._cleaned, self._comments = strip_comments(self._source)

        # Determine script type
        filename = getattr(self.struct, "filename", "") or ""
        _, ext = os.path.splitext(filename)
        ext_lower = ext.lower()

        if ext_lower == ".jse" or b"#@~^" in raw[:1024]:
            script_type = "JScript.Encoded"
        elif ext_lower in (".mjs", ".cjs"):
            script_type = "JavaScript (Node.js module)"
        else:
            script_type = "JavaScript"

        lib = detect_library(self._source)
        if lib:
            script_type += f" ({lib} library)"

        self.info = script_type
        self.reports["script_type"] = Report(
            f"{script_type}, encoding: {self._encoding}, {len(self._source)} chars",
            short=script_type,
            label="script_type",
            severity=Severity.INFO,
            verbosity=0,
            order=10,
        )

    def _compute_metrics(self):
        """Compute code metrics and obfuscation score."""
        if not hasattr(self, "_source"):
            return

        self._metrics = compute_metrics(self._source)
        score, indicators = obfuscation_score(self._metrics, self._source)

        # Map score to severity
        if score >= 81:
            sev = Severity.CRITICAL
        elif score >= 61:
            sev = Severity.HIGH
        elif score >= 41:
            sev = Severity.MEDIUM
        elif score >= 21:
            sev = Severity.LOW
        else:
            sev = Severity.INFO

        # Report verbosity: always show if HIGH+, else v1
        verbosity = 0 if sev <= Severity.HIGH else 1

        indicator_text = "\n".join(f"  - {ind}" for ind in indicators) if indicators else "  (none)"
        self.reports["obfuscation"] = Report(
            f"Obfuscation score: {score}/100 ({sev.name})\n{indicator_text}",
            short=f"Obfuscation: {score}/100 ({sev.name})",
            label="obfuscation",
            severity=sev,
            verbosity=verbosity,
            order=20,
            data={"score": score, "severity": sev.name, "indicators": indicators},
        )

    def _detect_threats(self):
        """Run threat pattern detection and kill chain analysis."""
        if not hasattr(self, "_source"):
            return

        # Also check after folding concatenations for fragmented API names
        folded = fold_string_concat(self._source)
        # Resolve fromCharCode into inline text for pattern scanning
        fcc_results = resolve_from_char_code(self._source)
        scan_source = folded
        for original, decoded in fcc_results:
            scan_source += "\n" + decoded

        findings = detect_threat_patterns(scan_source)

        # Also check fragmented API names
        fragmented = detect_api_fragmentation(self._source)
        for api in fragmented:
            findings.append({
                "pattern": "api_fragmentation",
                "description": f"API name reconstructed via string concatenation: {api}",
                "severity": "MEDIUM",
                "context": f"Fragmented: {api}",
            })

        # Emit individual threat reports
        for i, finding in enumerate(findings):
            sev = getattr(Severity, finding["severity"])
            self.reports[f"threat_{i}"] = Report(
                f"{finding['description']}\n  Context: ...{finding['context']}...",
                short=finding["description"],
                label=f"threat:{finding['pattern']}",
                severity=sev,
                verbosity=0,
                order=30 + i,
            )

        # Kill chain detection
        if detect_kill_chain(findings):
            self.reports["kill_chain"] = Report(
                "Kill chain detected: download + file write + execute components co-occur.\n"
                "This script has all components needed to download and execute a payload.",
                short="Kill chain: download + write + execute",
                label="kill_chain",
                severity=Severity.CRITICAL,
                verbosity=0,
                order=25,
            )

    def _extract_strings(self):
        """Resolve encoded strings and emit decoded content for IOC extraction."""
        if not hasattr(self, "_source"):
            return

        decoded_parts: list[str] = []

        # fromCharCode resolution
        fcc_results = resolve_from_char_code(self._source)
        for original, decoded in fcc_results:
            decoded_parts.append(f"fromCharCode: {decoded}")

        # Unescape hex/unicode in string literals
        literals = extract_string_literals(self._source)
        for lit in literals:
            if "\\x" in lit or "\\u" in lit:
                resolved = unescape_hex(unescape_unicode(lit))
                if resolved != lit:
                    decoded_parts.append(f"Escaped string: {resolved}")

        # String concatenation folding
        folded = fold_string_concat(self._source)
        if folded != self._source:
            # Find newly-visible string literals
            folded_lits = extract_string_literals(folded)
            original_lits = set(literals)
            for lit in folded_lits:
                if lit not in original_lits and len(lit) > 10:
                    decoded_parts.append(f"Concatenated: {lit}")

        if decoded_parts:
            text = "\n".join(decoded_parts)
            self.reports["decoded_strings"] = Report(
                text,
                short=f"{len(decoded_parts)} decoded string(s)",
                label="decoded_strings",
                severity=Severity.INFO,
                verbosity=2,
                order=60,
            )

            # Emit as child for PlainText IOC extraction
            child_text = "\n".join(decoded_parts)
            self.childitems.append(
                self.generate_struct(
                    data=child_text.encode("utf-8"),
                    filename="decoded_strings.txt",
                    mime_type="text/plain",
                )
            )

    def _extract_base64(self):
        """Detect and decode Base64 blobs, check for embedded binaries."""
        if not hasattr(self, "_source"):
            return

        blobs = extract_base64_blobs(self._source)
        if not blobs:
            return

        for i, (b64str, decoded) in enumerate(blobs):
            # Check for PE header (MZ)
            if decoded[:2] == b"MZ":
                sev = Severity.CRITICAL
                desc = f"Base64-encoded PE executable detected ({len(decoded)} bytes)"
            # Check for ZIP/PK magic
            elif decoded[:2] == b"PK":
                sev = Severity.HIGH
                desc = f"Base64-encoded ZIP archive detected ({len(decoded)} bytes)"
            # Check for ELF
            elif decoded[:4] == b"\x7fELF":
                sev = Severity.CRITICAL
                desc = f"Base64-encoded ELF binary detected ({len(decoded)} bytes)"
            else:
                sev = Severity.MEDIUM
                desc = f"Base64 blob decoded ({len(decoded)} bytes)"

            self.reports[f"base64_payload_{i}"] = Report(
                f"{desc}\n  Preview: {b64str[:60]}...",
                short=desc,
                label="base64_payload",
                severity=sev,
                verbosity=0,
                order=50 + i,
            )

            # Emit decoded blob as child
            self.childitems.append(
                self.generate_struct(
                    data=decoded,
                    filename=f"decoded_b64_{i}.bin",
                )
            )

    def _beautify(self):
        """Beautify source with jsbeautifier if available."""
        if not _JSBEAUTIFIER_AVAILABLE:
            return
        if not hasattr(self, "_source"):
            return

        try:
            beautified = jsbeautifier.beautify(self._source)
        except Exception as e:
            log.debug(f"jsbeautifier failed: {e}")
            return

        # Only emit if substantially different (>10% length change or many new lines)
        if abs(len(beautified) - len(self._source)) < len(self._source) * 0.10:
            orig_lines = self._source.count("\n")
            new_lines = beautified.count("\n")
            if abs(new_lines - orig_lines) < 5:
                return

        self.reports["beautified"] = Report(
            f"Beautified source available ({beautified.count(chr(10))} lines)",
            short="Beautified source available",
            label="beautified",
            severity=Severity.INFO,
            verbosity=2,
            order=70,
        )

        # Emit as text/plain child to avoid re-triggering ScriptAnalyzer
        self.childitems.append(
            self.generate_struct(
                data=beautified.encode("utf-8"),
                filename="beautified.js",
                mime_type="text/plain",
            )
        )

    def _detect_jse(self):
        """Detect JScript.Encode marker and decode."""
        raw = self.struct.rawdata
        decoded = detect_jse(raw)
        if decoded is None:
            return

        self.reports["jse_encoded"] = Report(
            f"JScript.Encode detected — decoded {len(decoded)} bytes",
            short="JScript.Encode detected",
            label="jse_encoded",
            severity=Severity.HIGH,
            verbosity=0,
            order=15,
        )

        # Emit decoded JS for recursive analysis
        self.childitems.append(
            self.generate_struct(
                data=decoded,
                filename="decoded.js",
                mime_type="application/javascript",
            )
        )

    def _deobfuscate(self):
        """Run JStillery / de4js deobfuscation and re-scan for threats."""
        if not hasattr(self, "_source"):
            return

        from Utils.js_tools import (
            jstillery_available, run_jstillery,
            de4js_available, run_de4js,
        )

        deobfuscated = None
        tool_name = None

        # Try JStillery first (AST-based, higher quality)
        if jstillery_available():
            deobfuscated = run_jstillery(self._source)
            if deobfuscated:
                tool_name = "JStillery"

        # Try de4js if JStillery didn't produce results
        if not deobfuscated and de4js_available():
            deobfuscated = run_de4js(self._source)
            if deobfuscated:
                tool_name = "de4js"

        if not deobfuscated:
            return

        self.reports["deobfuscated"] = Report(
            f"Deobfuscated by {tool_name} ({len(deobfuscated)} chars)",
            short=f"Deobfuscated via {tool_name}",
            label="deobfuscated", severity=Severity.INFO, verbosity=1, order=71,
        )

        # Re-scan deobfuscated source for threats the static pass missed
        new_findings = detect_threat_patterns(deobfuscated)
        existing_patterns = {r.label.split(":")[-1] for k, r in self.reports.items()
                            if k.startswith("threat_")}

        for finding in new_findings:
            if finding["pattern"] not in existing_patterns:
                idx = len([k for k in self.reports if k.startswith("threat_")])
                sev = getattr(Severity, finding["severity"])
                self.reports[f"threat_{idx}"] = Report(
                    f"[post-deobfuscation] {finding['description']}\n"
                    f"  Context: ...{finding['context']}...",
                    short=f"[deobf] {finding['description']}",
                    label=f"threat:{finding['pattern']}",
                    severity=sev, verbosity=0, order=30 + idx,
                )

        # Re-check kill chain with combined findings
        all_findings = detect_threat_patterns(self._source) + new_findings
        if "kill_chain" not in self.reports and detect_kill_chain(all_findings):
            self.reports["kill_chain"] = Report(
                "Kill chain detected (post-deobfuscation): download + write + execute",
                short="Kill chain: download + write + execute",
                label="kill_chain", severity=Severity.CRITICAL, verbosity=0, order=25,
            )

        # Emit deobfuscated source as child (text/plain to avoid re-trigger)
        self.childitems.append(self.generate_struct(
            data=deobfuscated.encode("utf-8"),
            filename="deobfuscated.js", mime_type="text/plain",
        ))

    def _dynamic(self):
        """Run box-js dynamic analysis."""
        from Utils.js_tools import boxjs_available, run_boxjs

        if not boxjs_available():
            return

        result = run_boxjs(self.struct.rawdata)
        if not result:
            return

        # --- URLs ---
        urls = result.get("urls", [])
        active_urls = result.get("active_urls", [])
        if urls:
            sev = Severity.CRITICAL if active_urls else Severity.HIGH
            url_text = "\n".join(
                f"  {'[ACTIVE] ' if u in active_urls else ''}{u}" for u in urls
            )
            self.reports["boxjs_urls"] = Report(
                f"box-js: {len(urls)} URL(s) requested"
                f" ({len(active_urls)} delivering payloads)\n{url_text}",
                short=f"box-js: {len(urls)} URL(s), {len(active_urls)} active",
                label="boxjs_urls", severity=sev, verbosity=0, order=26,
                data={"urls": urls, "active_urls": active_urls},
            )

        # --- IOCs ---
        iocs = result.get("ioc", [])
        if iocs:
            ioc_text = "\n".join(f"  {ioc}" for ioc in iocs[:20])
            self.reports["boxjs_iocs"] = Report(
                f"box-js: {len(iocs)} IOC(s)\n{ioc_text}",
                short=f"box-js: {len(iocs)} IOC(s)",
                label="boxjs_iocs", severity=Severity.HIGH, verbosity=0, order=27,
                data={"iocs": iocs},
            )

        # --- Snippets (executed code: JS, cmd, PowerShell) ---
        snippets = result.get("snippets", [])
        if snippets:
            for i, snippet in enumerate(snippets[:10]):
                snip_text = snippet if isinstance(snippet, str) else str(snippet)
                if len(snip_text) > 20:
                    self.childitems.append(self.generate_struct(
                        data=snip_text.encode("utf-8"),
                        filename=f"boxjs_snippet_{i}.txt",
                        mime_type="text/plain",
                    ))
            self.reports["boxjs_snippets"] = Report(
                f"box-js: {len(snippets)} code snippet(s) executed",
                short=f"box-js: {len(snippets)} snippet(s)",
                label="boxjs_snippets", severity=Severity.MEDIUM, verbosity=1, order=28,
            )

        # --- Resources (files written to disk) ---
        resources = result.get("resources", [])
        if resources:
            res_lines = []
            for res in resources[:10]:
                if isinstance(res, dict):
                    res_lines.append(
                        f"  {res.get('filename', '?')} ({res.get('type', 'unknown')})"
                    )
                else:
                    res_lines.append(f"  {res}")
            self.reports["boxjs_resources"] = Report(
                f"box-js: {len(resources)} file(s) written\n" + "\n".join(res_lines),
                short=f"box-js: {len(resources)} file(s) written",
                label="boxjs_resources", severity=Severity.HIGH, verbosity=0, order=29,
                data={"resources": resources},
            )

        # --- Extracted payloads as children ---
        for payload in result.get("payloads", []):
            self.childitems.append(self.generate_struct(
                data=payload["data"],
                filename=payload["filename"],
            ))
