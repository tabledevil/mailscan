"""Plain-text content analyzer.

Handles encoding detection (charset-normalizer) and language detection (lingua).
Replaces the old chardet/cchardet + pycld3/fasttext/langdetect stack with
modern, maintained alternatives that require no model downloads or C extensions.

Fallback chain:
  - Encoding: charset-normalizer -> chardet -> manual probe
  - Language: lingua -> (legacy detectors if present) -> None
"""

import logging
import textwrap

from Config.config import flags
from structure import Analyzer, Report, Severity
from Utils.plaintext_triage import (
    classify_plaintext,
    extract_password_candidates,
    language_detection_allowed,
    scan_text_for_expensive_extractors,
)

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

class PlainTextAnalyzer(Analyzer):
    compatible_mime_types = ["text/plain"]
    description = "Plain Textfile Analyser"
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
        if not language_detection_allowed(self.profile, self.text):
            self.reports["language_skipped"] = Report(
                f"Skipped language detection for {self.profile.kind}",
                label="language_skipped",
                verbosity=2,
            )
            return None

        language_text = self.text[: flags.plaintext_language_max_chars]

        # 1) lingua (preferred)
        if _LINGUA_AVAILABLE:
            try:
                detector = _get_lingua_detector()
                lang = detector.detect_language_of(language_text)
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
                resp = cld3.get_language(language_text)
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
                language = langdetect_detect(language_text)
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
        """Look for high-confidence password hints in likely human-readable text."""
        scan_text = self.scan_text
        if not scan_text:
            return

        candidates = extract_password_candidates(scan_text)
        if not candidates:
            return

        self.reports["password_hints"] = Report(
            f"{len(candidates)} high-confidence password hint(s)",
            label="password_hints",
            severity=Severity.MEDIUM,
            verbosity=1,
        )
        if _BROKER_AVAILABLE:
            for word in candidates:
                PasswordBroker.register_password(word, source_struct=self.struct)

    # ------------------------------------------------------------------
    # IOC extraction
    # ------------------------------------------------------------------
    def _extract_iocs(self):
        """Run IOC extraction on decoded text."""
        scan_text = self.scan_text
        if not _IOC_AVAILABLE or not scan_text:
            return

        try:
            iocs = extract_iocs(scan_text)
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
                    detail_lines.append(f"Password-like hints: {len(iocs.passwords)}")

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
        self.profile = None
        self.scan_text = ""

        self.modules["encoding"] = self._do_decode
        self.modules["triage"] = self._do_triage
        self.modules["language"] = self._do_language
        self.modules["passwords"] = self._scan_passwords
        self.modules["iocs"] = self._extract_iocs
        super().analysis()

        profile_kind = self.profile.kind if self.profile is not None else "unknown"
        self.info = f"{profile_kind}; language:{self.lang}"
        self.reports["summary"] = Report(
            self._summary_text(),
            short=textwrap.shorten(self._summary_text(), width=100) if self.text else "",
        )

    def _do_decode(self):
        self.text = self._decode(self.struct.rawdata)

    def _do_triage(self):
        self.profile = classify_plaintext(self.struct.rawdata, self.text)
        self.scan_text = scan_text_for_expensive_extractors(self.profile, self.text)

        details = [
            f"type={self.profile.kind}",
            f"sample={self.profile.sample_size}",
            f"size={self.profile.total_size}",
        ]
        if self.profile.reasons:
            details.append(f"reason={'; '.join(self.profile.reasons)}")
        self.reports["text_profile"] = Report(
            ", ".join(details),
            label="text_profile",
            verbosity=1,
        )
        if self.profile.external_hints:
            hint_text = "\n".join(
                f"{name}: {value}" for name, value in self.profile.external_hints.items()
            )
            self.reports["external_text_hints"] = Report(
                hint_text,
                label="external_text_hints",
                verbosity=2,
            )
        if self.profile.decoded_base64 is not None:
            filename = self._decoded_child_filename("base64.decoded")
            self.childitems.append(
                self.generate_struct(data=self.profile.decoded_base64, filename=filename)
            )
            self.reports["decoded_base64_child"] = Report(
                (
                    "Extracted base64 payload "
                    f"({len(self.profile.decoded_base64)} decoded bytes)"
                ),
                label="decoded_base64_child",
                severity=Severity.MEDIUM,
            )

    def _do_language(self):
        self.lang = self._detect_language()
        if self.lang is not None:
            self.reports["language"] = Report(self.lang)

    def _decoded_child_filename(self, suffix):
        filename = self.struct.filename if self.struct.has_filename else "decoded"
        return f"{filename}.{suffix}"

    def _summary_text(self):
        if self.profile is not None and self.profile.is_encoded:
            decoded_size = (
                len(self.profile.decoded_base64)
                if self.profile.decoded_base64 is not None
                else 0
            )
            return (
                f"Encoded text payload: {self.profile.kind}; "
                f"{self.struct.size} encoded bytes, {decoded_size} decoded bytes"
            )
        if len(self.text) > flags.plaintext_full_scan_bytes:
            return (
                f"Large text payload: {self.profile.kind if self.profile else 'unknown'}; "
                f"{len(self.text)} characters"
            )
        return self.text
