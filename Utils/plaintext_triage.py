"""Fast classification helpers for plain-text analysis."""

from __future__ import annotations

import base64
import binascii
import re
import shutil
import subprocess
from dataclasses import dataclass, field

from Config.config import flags


_BASE64_BYTES = set(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\r\n\t "
)
_BASE64_STRIP_RE = re.compile(rb"[\s]+")
_HTML_RE = re.compile(rb"^\s*(?:<!doctype\s+html\b|<html\b|<head\b|<body\b)", re.I)
_XML_RE = re.compile(rb"^\s*(?:<\?xml\b|<[a-z_][\w:.-]+(?:\s|>))", re.I)
_BATCH_RE = re.compile(
    rb"(?im)^\s*(?:@echo\s+off|setlocal\b|set\s+[\w\"%]|powershell(?:\.exe)?\b|cmd(?:\.exe)?\b)"
)
_POWERSHELL_RE = re.compile(
    rb"(?i)\b(?:powershell(?:\.exe)?|frombase64string|iex|invoke-expression|"
    rb"new-object\s+net\.webclient|downloadstring|encodedcommand)\b"
)
_VBS_RE = re.compile(
    rb"(?i)\b(?:wscript\.shell|createobject|vbscript|cscript(?:\.exe)?|wscript(?:\.exe)?)\b"
)


@dataclass
class TextProfile:
    kind: str
    sample_size: int
    total_size: int
    reasons: list[str] = field(default_factory=list)
    decoded_base64: bytes | None = None
    external_hints: dict[str, str] = field(default_factory=dict)

    @property
    def is_encoded(self) -> bool:
        return self.kind == "encoded_base64"

    @property
    def is_natural_text(self) -> bool:
        return self.kind == "natural_text"

    @property
    def is_script(self) -> bool:
        return self.kind.startswith("script_")

    @property
    def is_markup(self) -> bool:
        return self.kind in {"html", "xml"}


def classify_plaintext(raw: bytes, text: str | None = None) -> TextProfile:
    sample = raw[: flags.plaintext_sample_bytes]
    profile = TextProfile(
        kind="generic_text",
        sample_size=len(sample),
        total_size=len(raw),
    )

    _add_external_hints(profile, sample)

    decoded = _try_decode_base64(raw, sample)
    if decoded is not None:
        profile.kind = "encoded_base64"
        profile.decoded_base64 = decoded
        profile.reasons.append("base64-like content decoded cleanly")
        return profile

    lowered = sample.lower()
    if _HTML_RE.search(sample):
        profile.kind = "html"
        profile.reasons.append("html-like prefix")
    elif _looks_like_xml(sample):
        profile.kind = "xml"
        profile.reasons.append("xml-like prefix")
    elif _BATCH_RE.search(sample):
        profile.kind = "script_batch"
        profile.reasons.append("batch/cmd tokens")
    elif _POWERSHELL_RE.search(sample):
        profile.kind = "script_powershell"
        profile.reasons.append("powershell tokens")
    elif _VBS_RE.search(sample):
        profile.kind = "script_vbs"
        profile.reasons.append("vbs tokens")
    elif _looks_like_natural_text(text if text is not None else _decode_sample(sample)):
        profile.kind = "natural_text"
        profile.reasons.append("sentence-like prose")
    elif b"<script" in lowered:
        profile.kind = "html"
        profile.reasons.append("embedded script tag")

    return profile


def language_detection_allowed(profile: TextProfile, text: str) -> bool:
    if not text or len(text.strip()) < 10:
        return False
    if profile.is_encoded or profile.is_script or profile.is_markup:
        return False
    if len(text) > flags.plaintext_language_max_chars and not profile.is_natural_text:
        return False
    return len(text) <= flags.plaintext_full_scan_bytes or profile.is_natural_text


def scan_text_for_expensive_extractors(profile: TextProfile, text: str) -> str:
    if not text:
        return ""
    if len(text) <= flags.plaintext_full_scan_bytes:
        return text
    if profile.is_encoded:
        return ""

    candidates = []
    limit = flags.plaintext_sample_bytes
    for line in text[:limit].splitlines():
        lowered = line.lower()
        if (
            "password" in lowered
            or "passwort" in lowered
            or "kennwort" in lowered
            or "http://" in lowered
            or "https://" in lowered
            or "powershell" in lowered
            or "frombase64string" in lowered
        ):
            candidates.append(line)

    return "\n".join(candidates) if candidates else text[:limit]


def extract_password_candidates(text: str) -> list[str]:
    """Return high-confidence password hints only."""
    if not text:
        return []

    patterns = [
        re.compile(
            r"(?im)\b(?:password|passwort|kennwort|passcode|pw)\b\s*[:=\-]\s*"
            r"['\"]?([^\s'\"<>,;]{4,128})"
        ),
        re.compile(
            r"(?im)\b(?:password|passwort|kennwort)\b.{0,80}?\b(?:is|ist| lautet|:)\s*"
            r"['\"]?([^\s'\"<>,;]{4,128})"
        ),
        re.compile(
            r"(?im)\b(?:for|für|zum)\s+(?:the\s+)?(?:invoice|rechnung|application|"
            r"archive|zip|attachment|anhang).{0,80}?\b(?:password|passwort|kennwort)\b"
            r".{0,40}?\b(?:is|ist| lautet|:)\s*['\"]?([^\s'\"<>,;]{4,128})"
        ),
    ]

    candidates = []
    seen = set()
    for pattern in patterns:
        for match in pattern.finditer(text):
            candidate = match.group(1).strip().strip("\"'.,;:!?)")
            if _valid_password_candidate(candidate) and candidate not in seen:
                seen.add(candidate)
                candidates.append(candidate)
    return candidates


def _try_decode_base64(raw: bytes, sample: bytes) -> bytes | None:
    if len(raw) < flags.plaintext_encoded_min_bytes:
        return None
    if not sample:
        return None

    allowed_ratio = sum(byte in _BASE64_BYTES for byte in sample) / len(sample)
    if allowed_ratio < flags.plaintext_base64_min_ratio:
        return None

    stripped_sample = _BASE64_STRIP_RE.sub(b"", sample)
    if len(stripped_sample) < flags.plaintext_encoded_min_bytes:
        return None
    if not _has_base64_shape(sample, stripped_sample):
        return None

    stripped = _BASE64_STRIP_RE.sub(b"", raw)
    if len(stripped) % 4:
        return None

    try:
        decoded = base64.b64decode(stripped, validate=True)
    except (binascii.Error, ValueError):
        return None

    if not decoded or len(decoded) > flags.max_file_size:
        return None
    if not _decoded_payload_interesting(decoded):
        return None
    return decoded


def _has_base64_shape(sample: bytes, stripped_sample: bytes) -> bool:
    lines = [line.strip() for line in sample.splitlines() if line.strip()]
    long_lines = [line for line in lines if len(line) >= 64]
    if long_lines and len(long_lines) / max(len(lines), 1) >= 0.5:
        return True
    return len(stripped_sample) >= 16 * 1024


def _decoded_payload_interesting(decoded: bytes) -> bool:
    head = decoded[:4096]
    if head.startswith((b"MZ", b"PK\x03\x04", b"%PDF", b"\x7fELF")):
        return True
    if b"\x00" in head:
        return True
    printable = sum(byte in b"\r\n\t" or 32 <= byte < 127 for byte in head)
    return printable / max(len(head), 1) < 0.85


def _looks_like_xml(sample: bytes) -> bool:
    if not _XML_RE.search(sample):
        return False
    head = sample[:2048]
    return b"</" in head or b"/>" in head or b"?>" in head


def _looks_like_natural_text(text: str) -> bool:
    sample = text[:4096].strip()
    if len(sample) < 40:
        return False
    words = re.findall(r"[A-Za-zÄÖÜäöüß]{2,}", sample)
    if len(words) < 8:
        return False
    sentence_marks = sample.count(".") + sample.count("!") + sample.count("?")
    spaces = sample.count(" ")
    return sentence_marks > 0 and spaces / max(len(sample), 1) > 0.08


def _decode_sample(sample: bytes) -> str:
    return sample.decode("utf-8", errors="replace")


def _valid_password_candidate(candidate: str) -> bool:
    lowered = candidate.lower()
    if lowered in {"password", "passwort", "kennwort", "secret", "invoice"}:
        return False
    if len(candidate) < 4 or len(candidate) > 128:
        return False
    return not any(ch.isspace() for ch in candidate)


def _add_external_hints(profile: TextProfile, sample: bytes) -> None:
    if not flags.plaintext_external_tools_enabled or not sample:
        return

    commands = {
        "file": ["file", "--brief", "-"],
        "strings": ["strings", "-n", "8", "-"],
    }
    for name, args in commands.items():
        if shutil.which(args[0]) is None:
            continue
        try:
            proc = subprocess.run(
                args,
                input=sample,
                capture_output=True,
                timeout=flags.plaintext_tool_timeout,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        output = proc.stdout.decode("utf-8", errors="replace").strip()
        if output:
            profile.external_hints[name] = output[:500]
