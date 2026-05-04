"""Pure-function JavaScript static analysis engine.

All string extraction, deobfuscation, metrics, and pattern detection live
here so the analyzer class stays thin.
"""

import base64
import re
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def decode_js(raw: bytes) -> tuple[str, str]:
    """Decode raw bytes to text.  Returns (decoded_text, encoding_name)."""
    # BOM detection
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", errors="replace"), "UTF-16LE"
    if raw[:2] == b"\xfe\xff":
        return raw[2:].decode("utf-16-be", errors="replace"), "UTF-16BE"
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace"), "UTF-8-BOM"

    # Try UTF-8 strict first
    try:
        return raw.decode("utf-8"), "UTF-8"
    except UnicodeDecodeError:
        pass

    # charset-normalizer fallback
    try:
        from charset_normalizer import from_bytes
        result = from_bytes(raw).best()
        if result is not None:
            return str(result), result.encoding
    except ImportError:
        pass

    return raw.decode("latin-1"), "Latin-1"


# ---------------------------------------------------------------------------
# Comment stripping
# ---------------------------------------------------------------------------

def strip_comments(source: str) -> tuple[str, list[str]]:
    """Strip // and /* */ comments.  Returns (cleaned, comments_list).

    Respects string literals — won't strip inside quotes.
    """
    comments: list[str] = []
    result: list[str] = []
    i = 0
    length = len(source)

    while i < length:
        ch = source[i]

        # String literals — skip through
        if ch in ('"', "'", '`'):
            quote = ch
            j = i + 1
            while j < length:
                if source[j] == '\\':
                    j += 2
                    continue
                if source[j] == quote:
                    j += 1
                    break
                j += 1
            result.append(source[i:j])
            i = j
            continue

        # Regex literal heuristic — after certain tokens a / starts a regex
        if ch == '/' and i + 1 < length:
            next_ch = source[i + 1]

            # Single-line comment
            if next_ch == '/':
                end = source.find('\n', i)
                if end == -1:
                    end = length
                comments.append(source[i + 2:end].strip())
                i = end
                continue

            # Multi-line comment
            if next_ch == '*':
                end = source.find('*/', i + 2)
                if end == -1:
                    end = length
                else:
                    end += 2
                comments.append(source[i + 2:end - 2].strip() if end > i + 4 else "")
                result.append(' ')
                i = end
                continue

        result.append(ch)
        i += 1

    return ''.join(result), comments


# ---------------------------------------------------------------------------
# String extraction
# ---------------------------------------------------------------------------

def extract_string_literals(source: str) -> list[str]:
    """Extract single/double/backtick-quoted string literals with escape handling."""
    strings: list[str] = []
    i = 0
    length = len(source)

    while i < length:
        ch = source[i]
        if ch in ('"', "'", '`'):
            quote = ch
            j = i + 1
            parts: list[str] = []
            while j < length:
                if source[j] == '\\' and j + 1 < length:
                    parts.append(source[j:j + 2])
                    j += 2
                    continue
                if source[j] == quote:
                    strings.append(''.join(parts))
                    j += 1
                    break
                parts.append(source[j])
                j += 1
            i = j
        else:
            i += 1

    return strings


# ---------------------------------------------------------------------------
# Unescape helpers
# ---------------------------------------------------------------------------

_HEX_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})")
_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9a-fA-F]{4})")
_UNICODE_BRACE_RE = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}")


def unescape_hex(text: str) -> str:
    """Resolve \\xNN sequences."""
    return _HEX_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)


def unescape_unicode(text: str) -> str:
    """Resolve \\uNNNN and \\u{NNNNN} sequences."""
    text = _UNICODE_BRACE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    text = _UNICODE_ESCAPE_RE.sub(lambda m: chr(int(m.group(1), 16)), text)
    return text


# ---------------------------------------------------------------------------
# fromCharCode resolution
# ---------------------------------------------------------------------------

_FROM_CHAR_CODE_RE = re.compile(
    r"String\s*\.\s*fromCharCode\s*\(([^)]+)\)", re.IGNORECASE,
)


def resolve_from_char_code(source: str) -> list[tuple[str, str]]:
    """Find String.fromCharCode(...) calls, return (original, decoded) pairs."""
    results: list[tuple[str, str]] = []
    for m in _FROM_CHAR_CODE_RE.finditer(source):
        original = m.group(0)
        args_str = m.group(1)
        try:
            # Parse comma-separated args — decimal or 0xNN hex
            chars: list[str] = []
            for arg in args_str.split(","):
                arg = arg.strip()
                if not arg:
                    continue
                if arg.lower().startswith("0x"):
                    chars.append(chr(int(arg, 16)))
                else:
                    chars.append(chr(int(arg)))
            decoded = ''.join(chars)
            results.append((original, decoded))
        except (ValueError, OverflowError):
            continue
    return results


# ---------------------------------------------------------------------------
# Base64 blob extraction
# ---------------------------------------------------------------------------

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")


def extract_base64_blobs(source: str) -> list[tuple[str, bytes]]:
    """Find base64 strings >40 chars in string literals, decode them."""
    literals = extract_string_literals(source)
    results: list[tuple[str, bytes]] = []
    for lit in literals:
        for m in _BASE64_RE.finditer(lit):
            b64str = m.group(0)
            try:
                decoded = base64.b64decode(b64str, validate=True)
                # Sanity check: decoded should not be empty
                if decoded:
                    results.append((b64str, decoded))
            except Exception:
                continue
    return results


# ---------------------------------------------------------------------------
# String concatenation folding
# ---------------------------------------------------------------------------

_CONCAT_RE = re.compile(
    r"""(["'])([^"'\\]*(?:\\.[^"'\\]*)*)\1\s*\+\s*(["'])([^"'\\]*(?:\\.[^"'\\]*)*)\3""",
)


def fold_string_concat(source: str) -> str:
    """Fold literal concatenation: "he" + "llo" -> "hello".  Max 10 iterations."""
    for _ in range(10):
        new_source = _CONCAT_RE.sub(lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), source)
        if new_source == source:
            break
        source = new_source
    return source


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------

@dataclass
class JSMetrics:
    total_length: int = 0
    line_count: int = 0
    max_line_length: int = 0
    avg_line_length: float = 0.0
    string_literal_ratio: float = 0.0
    comment_ratio: float = 0.0
    hex_escape_count: int = 0
    unicode_escape_count: int = 0
    from_char_code_count: int = 0
    eval_count: int = 0
    base64_blob_count: int = 0
    single_char_identifier_ratio: float = 0.0


def compute_metrics(source: str) -> JSMetrics:
    """Compute structural metrics for obfuscation scoring."""
    m = JSMetrics()
    m.total_length = len(source)
    lines = source.splitlines()
    m.line_count = len(lines)
    if lines:
        line_lengths = [len(line) for line in lines]
        m.max_line_length = max(line_lengths)
        m.avg_line_length = sum(line_lengths) / len(lines)

    # String literal ratio
    literals = extract_string_literals(source)
    total_literal_len = sum(len(s) for s in literals)
    if m.total_length > 0:
        m.string_literal_ratio = total_literal_len / m.total_length

    # Comment ratio
    _, comments = strip_comments(source)
    total_comment_len = sum(len(c) for c in comments)
    if m.total_length > 0:
        m.comment_ratio = total_comment_len / m.total_length

    # Escape counts
    m.hex_escape_count = len(_HEX_ESCAPE_RE.findall(source))
    m.unicode_escape_count = len(_UNICODE_ESCAPE_RE.findall(source)) + len(_UNICODE_BRACE_RE.findall(source))
    m.from_char_code_count = len(_FROM_CHAR_CODE_RE.findall(source))

    # eval count
    m.eval_count = len(re.findall(r"\beval\s*\(", source))

    # Base64 blobs in string literals
    m.base64_blob_count = len(extract_base64_blobs(source))

    # Single-char identifier ratio — look for standalone single-letter var names
    identifiers = re.findall(r"\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b", source)
    # Filter out JS keywords
    _JS_KEYWORDS = {
        "var", "let", "const", "function", "return", "if", "else", "for",
        "while", "do", "switch", "case", "break", "continue", "new", "this",
        "typeof", "instanceof", "in", "of", "try", "catch", "finally",
        "throw", "delete", "void", "true", "false", "null", "undefined",
        "class", "extends", "super", "import", "export", "default", "from",
        "async", "await", "yield", "with", "debugger",
    }
    identifiers = [ident for ident in identifiers if ident not in _JS_KEYWORDS]
    if identifiers:
        single_char = sum(1 for ident in identifiers if len(ident) == 1)
        m.single_char_identifier_ratio = single_char / len(identifiers)

    return m


# ---------------------------------------------------------------------------
# Library detection (false-positive suppression)
# ---------------------------------------------------------------------------

KNOWN_LIBRARIES = [
    (re.compile(r"/\*!?\s*jQuery\s+v[\d.]+"), "jQuery"),
    (re.compile(r"/\*!?\s*React\s+v[\d.]+"), "React"),
    (re.compile(r"/\*!?\s*Bootstrap\s+v[\d.]+"), "Bootstrap"),
    (re.compile(r"/\*!?\s*Lodash\s+[\d.]+"), "Lodash"),
    (re.compile(r"/\*!?\s*Vue\.js\s+v[\d.]+"), "Vue.js"),
    (re.compile(r"/\*!?\s*Angular\s+v[\d.]+"), "Angular"),
    (re.compile(r"//# sourceMappingURL="), "source-mapped"),
    (re.compile(r"/\*!?\s*D3\.js"), "D3.js"),
    (re.compile(r"/\*!?\s*moment\.js"), "Moment.js"),
    (re.compile(r"/\*!?\s*underscore\.js"), "Underscore.js"),
]


def detect_library(source: str) -> str | None:
    """Return library name if a known banner is found, else None."""
    # Only check first 2000 chars — banners are at the top
    head = source[:2000]
    for pattern, name in KNOWN_LIBRARIES:
        if pattern.search(head):
            return name
    return None


# ---------------------------------------------------------------------------
# Obfuscation scoring
# ---------------------------------------------------------------------------

_JSFUCK_RE = re.compile(r"[\[\]()!+]{50,}")
_JJENCODE_RE = re.compile(r"\$=~\[\];")
_AAENCODE_RE = re.compile(r"\u0FF9|\u0E4F|\u2299")


def obfuscation_score(metrics: JSMetrics, source: str) -> tuple[int, list[str]]:
    """Score 0-100 with indicator list.

    Thresholds: 0-20=INFO, 21-40=LOW, 41-60=MEDIUM, 61-80=HIGH, 81+=CRITICAL
    """
    score = 0
    indicators: list[str] = []

    # Long lines
    if metrics.max_line_length > 5000:
        score += 15
        indicators.append(f"Very long line ({metrics.max_line_length} chars)")

    # No comments + long lines → suspicious
    if metrics.comment_ratio < 0.01 and metrics.max_line_length > 500 and metrics.total_length > 500:
        score += 10
        indicators.append("No comments with long lines")

    # High string literal ratio
    if metrics.string_literal_ratio > 0.60:
        score += 15
        indicators.append(f"High string literal ratio ({metrics.string_literal_ratio:.0%})")

    # Hex escapes
    if metrics.hex_escape_count > 20:
        score += 15
        indicators.append(f"Heavy hex escapes ({metrics.hex_escape_count})")

    # fromCharCode
    if metrics.from_char_code_count > 3:
        score += 15
        indicators.append(f"Frequent fromCharCode ({metrics.from_char_code_count} calls)")

    # eval
    if metrics.eval_count > 2:
        score += 10
        indicators.append(f"Multiple eval() calls ({metrics.eval_count})")

    # Single-char identifiers
    if metrics.single_char_identifier_ratio > 0.50 and metrics.total_length > 500:
        score += 10
        indicators.append(f"High single-char identifier ratio ({metrics.single_char_identifier_ratio:.0%})")

    # JSFuck/JJEncode/AAEncode — definitive obfuscation
    if _JSFUCK_RE.search(source):
        score += 40
        indicators.append("JSFuck pattern detected")
    if _JJENCODE_RE.search(source):
        score += 40
        indicators.append("JJEncode pattern detected")
    if _AAENCODE_RE.search(source):
        score += 40
        indicators.append("AAEncode pattern detected")

    # Library banner → reduce score
    lib = detect_library(source)
    if lib:
        score = max(0, score - 15)
        indicators.append(f"Known library detected: {lib}")

    score = min(100, max(0, score))
    return score, indicators


# ---------------------------------------------------------------------------
# Threat pattern detection
# ---------------------------------------------------------------------------

# CRITICAL — kill chain components, near-zero FP in email context
CRITICAL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # WScript.Shell + Run/Exec
    (re.compile(r"WScript\s*\.\s*Shell", re.IGNORECASE),
     "WScript.Shell", "WScript.Shell COM automation — classic JS dropper execution"),
    # MSXML2.XMLHTTP / WinHttp download cradle
    (re.compile(r"(?:MSXML2\.XMLHTTP|WinHttp\.WinHttpRequest|Microsoft\.XMLHTTP)", re.IGNORECASE),
     "download_cradle", "HTTP download cradle via COM object"),
    # PowerShell invocation
    (re.compile(r"(?:powershell(?:\.exe)?)\b", re.IGNORECASE),
     "powershell", "PowerShell invocation"),
    (re.compile(r"-(?:enc|encodedcommand)\b", re.IGNORECASE),
     "powershell_encoded", "PowerShell encoded command"),
    (re.compile(r"-(?:exec(?:utionpolicy)?)\s+bypass", re.IGNORECASE),
     "powershell_bypass", "PowerShell execution policy bypass"),
    # Shell.Application + ShellExecute
    (re.compile(r"Shell\s*\.\s*Application", re.IGNORECASE),
     "shell_execute", "Shell.Application COM automation — alt execution"),
    # ADODB.Stream + SaveToFile
    (re.compile(r"ADODB\s*\.\s*Stream", re.IGNORECASE),
     "file_write", "ADODB.Stream — file drop capability"),
    (re.compile(r"\.SaveToFile\s*\(", re.IGNORECASE),
     "file_write", "SaveToFile — writing payload to disk"),
    # Scripting.FileSystemObject + CreateTextFile
    (re.compile(r"Scripting\s*\.\s*FileSystemObject", re.IGNORECASE),
     "file_write", "Scripting.FileSystemObject — filesystem access"),
]

# HIGH — strong suspicion
HIGH_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # ActiveXObject (any)
    (re.compile(r"(?:new\s+)?ActiveXObject\s*\(", re.IGNORECASE),
     "activex", "ActiveXObject instantiation — Windows COM automation"),
    # eval with constructed argument
    (re.compile(r"\beval\s*\(\s*(?:[a-zA-Z_$]|String\.fromCharCode|unescape|atob)", re.IGNORECASE),
     "eval_dynamic", "eval() with dynamic/constructed argument"),
    # fromCharCode with many args
    (re.compile(r"String\s*\.\s*fromCharCode\s*\([^)]{30,}\)", re.IGNORECASE),
     "fromcharcode_long", "String.fromCharCode with many arguments"),
    # WMI
    (re.compile(r"winmgmts:", re.IGNORECASE),
     "wmi", "WMI access via winmgmts: moniker"),
    (re.compile(r"Win32_Process\s*\.\s*Create", re.IGNORECASE),
     "wmi_exec", "WMI process creation"),
    # Registry manipulation
    (re.compile(r"\.RegWrite\s*\(", re.IGNORECASE),
     "registry", "Registry write operation"),
    (re.compile(r"HKCU\\\\.*\\\\Run\b|HKLM\\\\.*\\\\Run\b", re.IGNORECASE),
     "registry_run", "Registry Run key manipulation — persistence"),
    # Scheduled tasks
    (re.compile(r"Schedule\s*\.\s*Service", re.IGNORECASE),
     "schtask", "Task Scheduler COM object"),
    (re.compile(r"\bschtasks\b", re.IGNORECASE),
     "schtask", "schtasks command — scheduled task creation"),
    # LOLBins
    (re.compile(r"cmd\s*(?:\.exe)?\s*/c\b", re.IGNORECASE),
     "cmd_exec", "cmd.exe /c execution"),
    (re.compile(r"\bmshta\b", re.IGNORECASE),
     "mshta", "mshta execution — script proxy"),
    (re.compile(r"\brundll32\b", re.IGNORECASE),
     "rundll32", "rundll32 execution — DLL proxy"),
    (re.compile(r"\bcertutil\b.*-urlcache", re.IGNORECASE),
     "certutil_download", "certutil -urlcache — download via LOLBin"),
    (re.compile(r"\bbitsadmin\b.*/transfer", re.IGNORECASE),
     "bitsadmin", "bitsadmin /transfer — download via LOLBin"),
    # Environment harvesting + conditional exit
    (re.compile(r"WScript\s*\.\s*Network", re.IGNORECASE),
     "env_harvest", "WScript.Network — environment harvesting"),
    (re.compile(r"%(?:APPDATA|TEMP|USERPROFILE|LOCALAPPDATA)%", re.IGNORECASE),
     "env_vars", "Environment variable expansion — payload staging path"),
    # Anti-sandbox sleep
    (re.compile(r"WScript\s*\.\s*Sleep\s*\(\s*(\d+)", re.IGNORECASE),
     "anti_sandbox", "WScript.Sleep — potential anti-sandbox delay"),
    # .Run() / .Exec() after shell objects
    (re.compile(r"\.\s*(?:Run|Exec)\s*\(", re.IGNORECASE),
     "execute", "Shell .Run()/.Exec() call — command execution"),
]

# MEDIUM — notable findings
MEDIUM_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Base64 / atob
    (re.compile(r"\batob\s*\(", re.IGNORECASE),
     "atob", "atob() — Base64 decoding"),
    # new Function()
    (re.compile(r"new\s+Function\s*\(", re.IGNORECASE),
     "new_function", "new Function() — dynamic code construction"),
    # setTimeout with string
    (re.compile(r"setTimeout\s*\(\s*[\"']", re.IGNORECASE),
     "settimeout_eval", "setTimeout with string argument — indirect eval"),
    # Unicode escapes hiding API names
    (re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}"),
     "unicode_hiding", "Unicode escape sequences — possible API name hiding"),
    # Very long single line
    (re.compile(r"^.{5000,}$", re.MULTILINE),
     "long_line", "Very long single line (>5000 chars)"),
    # .ResponseBody (download chain)
    (re.compile(r"\.ResponseBody\b", re.IGNORECASE),
     "download_cradle", "HTTP response body access — download chain"),
    # .Open + .Send (HTTP request chain)
    (re.compile(r"\.\s*Open\s*\(\s*[\"'](?:GET|POST)", re.IGNORECASE),
     "http_open", "HTTP request .Open() — network access"),
]


# ---------------------------------------------------------------------------
# PDF Reader DOM — patterns specific to JavaScript embedded in PDFs.
#
# These never fire on browser/Node JS because the API surface (app.*,
# Collab.*, util.*, media.*, this.*) is unique to Acrobat / Foxit /
# similar viewers. Each pattern below ties to a real exploit family:
#
#   util.printf %D/%S args  → CVE-2008-2992  (buffer overflow)
#   Collab.collectEmailInfo → CVE-2007-5659  (classic Adobe sandbox escape)
#   media.newPlayer         → CVE-2009-4324
#   app.beginPriv/endPriv   → Acrobat privilege elevation
#   getAnnots overflow      → CVE-2009-1492
#
# Heap-spray fingerprints (NOP sled / shellcode constants) are language-
# generic but appear most often in PDF JS, so they live here too.
# ---------------------------------------------------------------------------

PDF_CRITICAL_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # CVE-2008-2992 — util.printf with hostile *width-augmented* format
    # args. The CVE is triggered by oversized width fields (e.g.
    # ``%4500D``, ``%5000f``) that overflow the format-string handling
    # code. Audit findings (codex_detect_corr_1: false-positive on
    # benign ``util.printf("%d", n)``; codex_detect_corr_2: too-narrow,
    # misses ``%f`` exploit shape). Require a long width specifier
    # (>= 3 digits) covering both /d/D and /f/F.
    (re.compile(
        # %  optional flag  required oversized width (>= 3 digits)
        # optional precision  conversion char
        r"util\s*\.\s*printf\s*\(\s*[\"'][^\"']*?"
        r"%[-+ #0]?\d{3,}(?:\.\d+)?\s*[DdFf]",
        re.IGNORECASE,
     ),
     "pdf_cve_2008_2992",
     "util.printf with oversized format width — CVE-2008-2992 buffer overflow"),
    # CVE-2007-5659 — Collab.collectEmailInfo (any reference is a strong
    # signal). Audit finding (codex_detect_corr_1): description was
    # "sandbox escape" but the public references describe a buffer
    # overflow primitive triggered by malformed/long arguments.
    (re.compile(r"Collab\s*\.\s*collectEmailInfo\b"),
     "pdf_cve_2007_5659",
     "Collab.collectEmailInfo — CVE-2007-5659 buffer overflow"),
    # CVE-2009-4324 — media.newPlayer
    (re.compile(r"media\s*\.\s*newPlayer\b"),
     "pdf_cve_2009_4324", "media.newPlayer — CVE-2009-4324 use-after-free"),
    # CVE-2009-1492 — getAnnots overflow. The exploit primitive is
    # ``nStart`` with a value relationship to ``nEnd`` (e.g. nStart < 0
    # or nStart > nEnd). Audit finding (codex_detect_corr_1, _2): the
    # original regex matched mere presence of ``nStart`` which fires
    # on benign range-based getAnnots(). Require both nStart and nEnd
    # in the same call to better approximate the exploit shape.
    (re.compile(r"getAnnots\s*\(\s*\{[^}]*?nStart[^}]*?nEnd"),
     "pdf_cve_2009_1492",
     "getAnnots() with nStart+nEnd range — CVE-2009-1492 overflow"),
    # CVE-2009-1493 — Doc.spell.customDictionaryOpen. Audit finding
    # (codex_detect_corr_1, _2): the upstream label was wrong —
    # CVE-2009-0658 is the unrelated JBIG2 issue from Feb 2009.
    # customDictionaryOpen is CVE-2009-1493 (Unix/Linux Reader/Acrobat
    # buffer overflow).
    (re.compile(r"\.\s*spell\s*\.\s*customDictionaryOpen\b"),
     "pdf_cve_2009_1493",
     "spell.customDictionaryOpen — CVE-2009-1493 buffer overflow"),
    # Heap-spray NOP sled (\x90 or %u9090 repeated)
    (re.compile(r"(?:%u9090){10,}|(?:\\x90){20,}|(?:\\u9090){10,}"),
     "pdf_heap_spray", "Heap-spray NOP sled — classic exploit primitive"),
    # Additional heap-spray fill patterns (per-user request — niche
    # carry-over from the audit triage). Each fingerprint matches
    # specific bytes used by published exploit PoCs to seed the heap:
    #
    #   IE5/6 spray fill ``0c0c0c0c`` — seed bytes for the historic
    #     Internet Explorer JavaScript spray that crossed over into
    #     PDF JS exploits via shared spray helpers.
    #   Long ``41414141`` runs (``AAAA``) — generic shellcode/stack
    #     placeholder fill seen in PoC Acrobat exploits.
    #   ``%41%41%41…`` URL-encoded variant of the same.
    (re.compile(r"(?:0c0c0c0c){8,}|(?:%u0c0c){10,}"),
     "pdf_heap_spray_0c0c", "0c0c0c0c heap-spray fill (IE/Adobe family)"),
    (re.compile(r"(?:41414141){8,}|(?:%u4141){10,}|(?:%41){30,}"),
     "pdf_heap_spray_aaaa",
     "Long AAAA / 41414141 heap-spray fill — PoC shellcode placeholder"),
    # Common Acrobat-era marker bytes left in published PoCs:
    #   ``unescape("%uNSCK")`` / ``%uNSCM`` — sentinel constants in
    #   metasploit-style Acrobat sled wrappers.
    (re.compile(r"%u(?:NSCK|NSCM)\b", re.IGNORECASE),
     "pdf_heap_spray_marker",
     "Metasploit-style spray sentinel — published PoC marker"),
    # Privilege elevation context
    (re.compile(r"app\s*\.\s*beginPriv\s*\(", re.IGNORECASE),
     "pdf_privilege_elevation",
     "app.beginPriv — Acrobat privileged-context entry"),
]

PDF_HIGH_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Trust-Manager bypass — any of these in a JS payload is unusual
    (re.compile(r"app\s*\.\s*trustedFunction\s*\(", re.IGNORECASE),
     "pdf_trusted_function", "app.trustedFunction — trust manager bypass"),
    (re.compile(r"app\s*\.\s*trustPropagatorFunction\s*\(", re.IGNORECASE),
     "pdf_trust_propagator", "app.trustPropagatorFunction — trust propagation"),
    # Outbound URL opening
    (re.compile(r"app\s*\.\s*launchURL\s*\(", re.IGNORECASE),
     "pdf_launch_url", "app.launchURL — outbound URL navigation"),
    # External file launch via this.exportDataObject({cName, nLaunch}).
    # Audit finding (codex_detect_corr_1; HIGH): the original regex
    # matched any ``cName`` parameter, firing on benign attachment
    # export. The exploit primitive specifically requires ``nLaunch``
    # set to a non-zero value (1=open with default app, 2=launch).
    # Require ``nLaunch`` somewhere in the same call.
    (re.compile(r"\.\s*exportDataObject\s*\([^)]*?nLaunch\s*:\s*[1-9]",
                re.IGNORECASE),
     "pdf_export_data",
     "exportDataObject(nLaunch>0) — extract+launch embedded payload"),
    # File-system access via Doc.saveAs
    (re.compile(r"\.\s*saveAs\s*\(", re.IGNORECASE),
     "pdf_save_as", "Doc.saveAs — disk write capability"),
    # Menu-item automation (silent print, save, etc.)
    (re.compile(r"app\s*\.\s*execMenuItem\s*\(", re.IGNORECASE),
     "pdf_exec_menu_item", "app.execMenuItem — Acrobat menu automation"),
    # getAnnots harvesting — only flag the abusive object-arg form so
    # we don't fire on benign ``this.getAnnots()`` enumeration loops.
    # Audit finding (codex_detect_corr_1, _2): the original regex
    # double-fired with the CRITICAL CVE detector on the same site.
    (re.compile(r"\.\s*getAnnots\s*\(\s*\{", re.IGNORECASE),
     "pdf_get_annots",
     "getAnnots({…}) with options — annotation harvest"),
    # this.submitForm to external URL — both shapes:
    #   submitForm("https://...")            (positional string)
    #   submitForm({cURL: "https://..."})    (object form)
    # Audit finding (codex_detect_corr_1; HIGH): object-form was
    # invisible to the previous matcher.
    (re.compile(
        r"\.\s*submitForm\s*\(\s*"
        r"(?:[\"'](?:https?|ftp|file)://"
        r"|\{[^}]*?cURL\s*:\s*[\"'](?:https?|ftp|file)://)",
        re.IGNORECASE,
     ),
     "pdf_submit_form_url",
     "this.submitForm to external URL — exfiltration (string or {cURL})"),
]

PDF_MEDIUM_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    # Generic Reader APIs that are notable but common in legit fillable forms
    (re.compile(r"app\s*\.\s*alert\s*\(", re.IGNORECASE),
     "pdf_app_alert", "app.alert — Acrobat dialog (test-PoC and legit forms)"),
    (re.compile(r"\.\s*setAction\s*\(", re.IGNORECASE),
     "pdf_set_action", "Field.setAction — programmatic action assignment"),
    (re.compile(r"\.\s*importTextData\s*\(", re.IGNORECASE),
     "pdf_import_text_data", "importTextData — external data ingestion"),
    (re.compile(r"util\s*\.\s*printd\s*\(", re.IGNORECASE),
     "pdf_util_printd", "util.printd — date format function (CVE-prone)"),
]


def detect_threat_patterns(source: str) -> list[dict]:
    """Run all pattern checks.  Returns list of dicts with keys:
    pattern, description, severity, context.
    """
    findings: list[dict] = []
    seen_patterns: set[str] = set()

    for severity_name, patterns in [
        ("CRITICAL", CRITICAL_PATTERNS + PDF_CRITICAL_PATTERNS),
        ("HIGH", HIGH_PATTERNS + PDF_HIGH_PATTERNS),
        ("MEDIUM", MEDIUM_PATTERNS + PDF_MEDIUM_PATTERNS),
    ]:
        for regex, pattern_name, description in patterns:
            m = regex.search(source)
            if m and pattern_name not in seen_patterns:
                seen_patterns.add(pattern_name)
                # Extract context (surrounding text)
                start = max(0, m.start() - 30)
                end = min(len(source), m.end() + 30)
                context = source[start:end].replace('\n', ' ').strip()
                findings.append({
                    "pattern": pattern_name,
                    "description": description,
                    "severity": severity_name,
                    "context": context,
                })

    return findings


# Kill chain categories for co-occurrence detection
_KILL_CHAIN_DOWNLOAD = {"download_cradle", "http_open", "certutil_download", "bitsadmin"}
_KILL_CHAIN_WRITE = {"file_write"}
_KILL_CHAIN_EXECUTE = {
    "WScript.Shell", "execute", "shell_execute", "powershell",
    "cmd_exec", "mshta", "rundll32", "wmi_exec",
}


def detect_kill_chain(findings: list[dict]) -> bool:
    """True if download + file_write + execute components all co-occur."""
    found_patterns = {f["pattern"] for f in findings}
    has_download = bool(found_patterns & _KILL_CHAIN_DOWNLOAD)
    has_write = bool(found_patterns & _KILL_CHAIN_WRITE)
    has_execute = bool(found_patterns & _KILL_CHAIN_EXECUTE)
    return has_download and has_write and has_execute


# ---------------------------------------------------------------------------
# API name fragmentation detection
# ---------------------------------------------------------------------------

_FRAGMENTATION_TARGETS = [
    "WScript.Shell",
    "WScript.Network",
    "Scripting.FileSystemObject",
    "MSXML2.XMLHTTP",
    "ADODB.Stream",
    "Shell.Application",
    "Schedule.Service",
    "ActiveXObject",
]


def detect_api_fragmentation(source: str) -> list[str]:
    """Detect API names reconstructed via string concatenation."""
    folded = fold_string_concat(source)
    found: list[str] = []
    for api in _FRAGMENTATION_TARGETS:
        # Check if the API appears after folding but NOT in the original source
        if api.lower() in folded.lower() and api.lower() not in source.lower():
            found.append(api)
    return found


# ---------------------------------------------------------------------------
# JScript Encoded detection + decode
# ---------------------------------------------------------------------------

_JSE_MARKER = b"#@~^"

# JScript.Encode decoding table
_JSE_DECODE_TABLE = (
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f"
    "\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"
    "\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f"
    "\x30\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f"
    "\x40\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f"
    "\x50\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f"
    "\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f"
    "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f"
)

# The actual JScript Encoded cipher tables (3 substitution alphabets,
# cycled per-character).  Each maps an encoded byte to a plaintext byte.
_JSE_PICK = [1, 2, 0, 1, 2, 0, 2, 0, 1]

_JSE_ALPHA = [
    [0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a,
     0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54,
     0x55, 0x56, 0x57, 0x58, 0x59, 0x5a],
    [0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a,
     0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74,
     0x75, 0x76, 0x77, 0x78, 0x79, 0x7a],
    [0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39],
]

_JSE_DECODE = [
    [0x64, 0x37, 0x69, 0x50, 0x7e, 0x2c, 0x22, 0x5a, 0x65, 0x4a,
     0x45, 0x72, 0x61, 0x28, 0x5b, 0x5c, 0x3d, 0x48, 0x66, 0x75,
     0x55, 0x63, 0x44, 0x74, 0x6a, 0x59],
    [0x35, 0x68, 0x39, 0x76, 0x42, 0x73, 0x24, 0x4c, 0x23, 0x5f,
     0x49, 0x52, 0x4b, 0x54, 0x43, 0x67, 0x38, 0x71, 0x6e, 0x6d,
     0x34, 0x4f, 0x57, 0x53, 0x7d, 0x46],
    [0x2a, 0x7c, 0x21, 0x25, 0x7b, 0x30, 0x29, 0x36, 0x6c, 0x6f],
]


def detect_jse(raw: bytes) -> bytes | None:
    """Detect JScript.Encode marker and decode.  Returns decoded bytes or None."""
    marker_pos = raw.find(_JSE_MARKER)
    if marker_pos == -1:
        return None

    # Find the encoded body between #@~^ and ^#~@
    start = marker_pos + len(_JSE_MARKER)
    # Skip the length field and == delimiter
    eq_pos = raw.find(b"==", start)
    if eq_pos == -1:
        return None
    body_start = eq_pos + 2

    end_marker = raw.find(b"==^#~@", body_start)
    if end_marker == -1:
        return None

    encoded = raw[body_start:end_marker]

    # Decode
    result: list[int] = []
    char_index = 0
    i = 0
    while i < len(encoded):
        byte = encoded[i]

        # Escape sequences
        if byte == 0x40:  # @
            if i + 1 < len(encoded):
                i += 1
                result.append(encoded[i])
            i += 1
            continue

        # Check which alphabet this byte belongs to
        decoded = False
        pick_idx = _JSE_PICK[char_index % 9]
        for alpha_idx in range(3):
            if byte in _JSE_ALPHA[alpha_idx]:
                pos = _JSE_ALPHA[alpha_idx].index(byte)
                if pos < len(_JSE_DECODE[alpha_idx]):
                    result.append(_JSE_DECODE[alpha_idx][pos])
                else:
                    result.append(byte)
                decoded = True
                char_index += 1
                break

        if not decoded:
            result.append(byte)

        i += 1

    return bytes(result)
