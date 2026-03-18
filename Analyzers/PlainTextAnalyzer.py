"""Plain-text content analyzer.

Handles encoding detection (charset-normalizer) and language detection (lingua).
Replaces the old chardet/cchardet + pycld3/fasttext/langdetect stack with
modern, maintained alternatives that require no model downloads or C extensions.

Fallback chain:
  - Encoding: charset-normalizer -> chardet -> manual probe
  - Language: lingua -> (legacy detectors if present) -> None
"""

import logging
import re
import textwrap

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

# --- Password broker ---
try:
    from Utils.password_broker import PasswordBroker

    _BROKER_AVAILABLE = True
except ImportError:
    _BROKER_AVAILABLE = False

# --- IOC extraction ---
try:
    from Utils.ioc_extractor import extract_iocs

    _IOC_AVAILABLE = True
except ImportError:
    _IOC_AVAILABLE = False

# --- Encoding detection ---
try:
    import charset_normalizer

    _CHARSET_NORMALIZER = True
except ImportError:
    _CHARSET_NORMALIZER = False

try:
    import chardet
except ImportError:
    chardet = None

# --- Language detection (new: lingua) ---
try:
    from lingua import Language, LanguageDetectorBuilder

    # Build detector once (lazy singleton)
    _lingua_detector = None

    def _get_lingua_detector():
        global _lingua_detector
        if _lingua_detector is None:
            _lingua_detector = (
                LanguageDetectorBuilder.from_all_languages().with_low_accuracy_mode().build()
            )
        return _lingua_detector

    _LINGUA_AVAILABLE = True
except ImportError:
    _LINGUA_AVAILABLE = False

# --- Legacy language detectors (graceful fallback) ---
try:
    import cld3
except ImportError:
    cld3 = None

try:
    from langdetect import detect as langdetect_detect
    from langdetect import lang_detect_exception
except ImportError:
    langdetect_detect = None
    lang_detect_exception = None

# Password pattern — matches English and German keywords
_RE_FIND_PW = re.compile(r"(pw|kennwort|pass(wor[dt])?)\s*[:\-=]?\s*(?P<words>.*)", re.IGNORECASE)


class PlainTextAnalyzer(Analyzer):
    compatible_mime_types = ["text/plain"]
    description = "Plain Textfile Analyser"
    specificity = 5
    optional_pip_dependencies = [
        ("lingua", "lingua-language-detector"),
    ]
    extra = "lang"

    # ------------------------------------------------------------------
    # Encoding detection
    # ------------------------------------------------------------------
    def _decode(self, raw: bytes) -> str:
        """Decode raw bytes to str using the best available method."""
        if isinstance(raw, str):
            return raw

        # Fast path: try UTF-8 first (most common)
        try:
            decoded = raw.decode("utf-8")
            self.reports["encoding"] = Report("utf-8")
            return decoded
        except UnicodeDecodeError:
            pass

        # charset-normalizer (preferred)
        if _CHARSET_NORMALIZER:
            result = charset_normalizer.from_bytes(raw).best()
            if result is not None:
                encoding = result.encoding
                self.reports["encoding"] = Report(encoding)
                return str(result)

        # chardet fallback
        if chardet is not None:
            detection = chardet.detect(raw)
            enc = detection.get("encoding")
            if enc:
                self.reports["encoding"] = Report(enc)
                try:
                    return raw.decode(enc, errors="replace")
                except (UnicodeDecodeError, LookupError):
                    pass

        # Last resort: try common encodings
        for enc in ("utf-8-sig", "utf-16", "iso-8859-15", "windows-1252"):
            try:
                decoded = raw.decode(enc, errors="replace")
                self.reports["encoding"] = Report(enc)
                return decoded
            except (UnicodeDecodeError, LookupError):
                pass

        # Give up — force decode
        self.reports["encoding"] = Report("utf-8 (forced)")
        return raw.decode("utf-8", errors="replace")

    # ------------------------------------------------------------------
    # Language detection
    # ------------------------------------------------------------------
    def _detect_language(self) -> str | None:
        """Detect the language of self.text using the best available detector."""
        if not self.text or len(self.text.strip()) < 10:
            return None

        # 1) lingua (preferred)
        if _LINGUA_AVAILABLE:
            try:
                detector = _get_lingua_detector()
                lang = detector.detect_language_of(self.text)
                if lang is not None:
                    iso = lang.iso_code_639_1.name.lower()
                    self.reports["lang_lingua"] = Report(
                        f"{lang.name} ({iso})",
                        label="lang_lingua",
                        verbosity=2,
                    )
                    return iso
            except Exception as e:
                log.debug(f"lingua detection failed: {e}")

        # 2) cld3 fallback
        if cld3 is not None:
            try:
                resp = cld3.get_language(self.text)
                if resp and resp.is_reliable:
                    self.reports["lang_cld3"] = Report(
                        f"{resp.language}@{resp.probability:.2f}",
                        label="lang_cld3",
                        verbosity=2,
                    )
                    return resp.language
            except Exception as e:
                log.debug(f"cld3 detection failed: {e}")

        # 3) langdetect fallback
        if langdetect_detect is not None:
            try:
                language = langdetect_detect(self.text)
                self.reports["lang_langdetect"] = Report(
                    language, label="lang_langdetect", verbosity=2
                )
                return language
            except Exception as e:
                log.debug(f"langdetect detection failed: {e}")

        log.debug("No language detection module available or working")
        return None

    # ------------------------------------------------------------------
    # Password scanning
    # ------------------------------------------------------------------
    def _scan_passwords(self):
        """Look for password hints in the text body."""
        if not self.text:
            return

        match = _RE_FIND_PW.search(self.text)
        if match:
            words = [w for w in match.group("words").split() if len(w) > 3]
            if words:
                self.reports["possible_passwords"] = Report(
                    ",".join(words),
                    label="possible_passwords",
                    severity=Severity.HIGH,
                    verbosity=0,
                )
                if _BROKER_AVAILABLE:
                    for word in words:
                        PasswordBroker.register_password(word, source_struct=self.struct)

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------
    def _extract_iocs(self):
        """Run IOC extraction on decoded text."""
        if not _IOC_AVAILABLE or not self.text:
            return

        try:
            iocs = extract_iocs(self.text)
            if iocs.has_findings:
                parts = iocs.summary_parts()
                summary_text = ", ".join(parts)

                # Build detailed report
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
                    if _BROKER_AVAILABLE:
                        for pw in iocs.passwords:
                            PasswordBroker.register_password(pw, source_struct=self.struct)

                self.reports["iocs"] = Report(
                    "\n".join(detail_lines),
                    short=summary_text,
                    label="iocs",
                    severity=Severity.MEDIUM if (iocs.urls or iocs.ipv4) else Severity.INFO,
                    verbosity=1,
                )

                # Store IOC result on struct for upstream consumers (e.g. password retry)
                self._ioc_result = iocs
        except Exception as e:
            log.debug(f"IOC extraction failed: {e}")

    # ------------------------------------------------------------------
    # Main analysis
    # ------------------------------------------------------------------
    def analysis(self):
        self.text = ""
        self.lang = None
        self._ioc_result = None

        self.modules["encoding"] = self._do_decode
        self.modules["language"] = self._do_language
        self.modules["passwords"] = self._scan_passwords
        self.modules["iocs"] = self._extract_iocs
        super().analysis()

        self.info = f"language:{self.lang}"
        self.reports["summary"] = Report(
            self.text,
            short=textwrap.shorten(self.text, width=100) if self.text else "",
        )

    def _do_decode(self):
        self.text = self._decode(self.struct.rawdata)

    def _do_language(self):
        self.lang = self._detect_language()
        self.reports["language"] = Report(self.lang)
