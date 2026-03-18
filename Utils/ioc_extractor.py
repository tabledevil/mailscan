"""IOC (Indicator of Compromise) extraction from text.

Extracts:
  - IPv4 and IPv6 addresses
  - URLs (http/https/ftp)
  - Email addresses
  - Domain names
  - File hashes (MD5, SHA1, SHA256)
  - Passwords (from keyword context)

Uses custom regexes.  Optional ``ioc-fanger`` integration for defanging
(e.g. hxxp[://] -> http://) is supported but not required.

All extraction functions return deduplicated lists preserving first-seen order.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("matt")

# Try to import ioc-fanger for refanging obfuscated IOCs
try:
    import ioc_fanger

    _FANGER_AVAILABLE = True
except ImportError:
    _FANGER_AVAILABLE = False


# ------------------------------------------------------------------
# Regex patterns
# ------------------------------------------------------------------

# IPv4 — standard dotted-quad, avoiding version numbers and timestamps
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"
)

# IPv6 — simplified pattern covering common representations
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b"
    r"|"
    r"\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b"
    r"|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}\b"
)

# URLs — http, https, ftp; also matches defanged hxxp variants
_RE_URL = re.compile(
    r"(?:h[tx]{2}ps?|ftp)://"  # scheme (also hxxp, hXXp)
    r"[^\s<>\"\'\)\]\}]{3,}",  # rest of URL
    re.IGNORECASE,
)

# Email addresses
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")

# Domain names — requires at least one dot and a valid TLD
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,13})\b"
)

# Hashes
_RE_MD5 = re.compile(r"\b[0-9a-fA-F]{32}\b")
_RE_SHA1 = re.compile(r"\b[0-9a-fA-F]{40}\b")
_RE_SHA256 = re.compile(r"\b[0-9a-fA-F]{64}\b")

# Password patterns (English + German keywords)
_RE_PASSWORD = re.compile(
    r"(?:pw|kennwort|passwor[dt]|password|passcode)\s*[:\-=\s]\s*(\S+)",
    re.IGNORECASE,
)

# Common false-positive domains to skip
_DOMAIN_SKIPLIST = frozenset(
    {
        "w3.org",
        "schemas.openxmlformats.org",
        "schemas.microsoft.com",
        "www.w3.org",
        "xml.org",
        "xmlsoap.org",
        "purl.org",
        "example.com",
        "example.org",
        "example.net",
    }
)

# Private/reserved IPv4 ranges to optionally filter
_PRIVATE_RANGES = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("169.254.0.0/16"),
]


# ------------------------------------------------------------------
# Result dataclass
# ------------------------------------------------------------------


@dataclass
class IOCResult:
    """Collection of extracted IOCs from a text."""

    ipv4: list[str] = field(default_factory=list)
    ipv6: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    md5: list[str] = field(default_factory=list)
    sha1: list[str] = field(default_factory=list)
    sha256: list[str] = field(default_factory=list)
    passwords: list[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return (
            len(self.ipv4)
            + len(self.ipv6)
            + len(self.urls)
            + len(self.emails)
            + len(self.domains)
            + len(self.md5)
            + len(self.sha1)
            + len(self.sha256)
            + len(self.passwords)
        )

    @property
    def has_findings(self) -> bool:
        return self.total_count > 0

    def summary_parts(self) -> list[str]:
        """Return a list of 'N type(s)' strings for non-empty categories."""
        parts = []
        if self.ipv4:
            parts.append(f"{len(self.ipv4)} IPv4")
        if self.ipv6:
            parts.append(f"{len(self.ipv6)} IPv6")
        if self.urls:
            parts.append(f"{len(self.urls)} URL(s)")
        if self.emails:
            parts.append(f"{len(self.emails)} email(s)")
        if self.domains:
            parts.append(f"{len(self.domains)} domain(s)")
        if self.md5:
            parts.append(f"{len(self.md5)} MD5")
        if self.sha1:
            parts.append(f"{len(self.sha1)} SHA1")
        if self.sha256:
            parts.append(f"{len(self.sha256)} SHA256")
        if self.passwords:
            parts.append(f"{len(self.passwords)} password(s)")
        return parts

    def to_dict(self) -> dict:
        return {
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "urls": self.urls,
            "emails": self.emails,
            "domains": self.domains,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "passwords": self.passwords,
        }


# ------------------------------------------------------------------
# Helper: deduplicate preserving order
# ------------------------------------------------------------------


def _dedup(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result = []
    for item in items:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            result.append(item)
    return result


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IPv4 address is in a private/reserved range."""
    try:
        addr = ipaddress.IPv4Address(ip_str)
        return any(addr in net for net in _PRIVATE_RANGES)
    except (ipaddress.AddressValueError, ValueError):
        return False


# ------------------------------------------------------------------
# Main extraction function
# ------------------------------------------------------------------


def extract_iocs(
    text: str,
    *,
    include_private_ips: bool = False,
    skip_domains: Optional[set[str]] = None,
) -> IOCResult:
    """Extract IOCs from *text*.

    Args:
        text: Input text to scan.
        include_private_ips: If False (default), filter out RFC1918/loopback IPs.
        skip_domains: Additional domains to skip (merged with built-in skiplist).

    Returns:
        IOCResult with deduplicated findings.
    """
    if not text:
        return IOCResult()

    # Optionally refang obfuscated IOCs before extraction
    if _FANGER_AVAILABLE:
        try:
            text = ioc_fanger.fang(text)
        except Exception:
            pass  # If fanger fails, continue with original text

    domain_skip = _DOMAIN_SKIPLIST | (skip_domains or set())

    result = IOCResult()

    # SHA256 first (64 hex chars) — must extract before MD5/SHA1 to avoid
    # substring matches
    sha256_matches = _RE_SHA256.findall(text)
    result.sha256 = _dedup(sha256_matches)
    sha256_set = {h.lower() for h in result.sha256}

    # SHA1 (40 hex chars)
    sha1_matches = [h for h in _RE_SHA1.findall(text) if h.lower() not in sha256_set]
    result.sha1 = _dedup(sha1_matches)
    sha1_set = {h.lower() for h in result.sha1} | sha256_set

    # MD5 (32 hex chars)
    md5_matches = [h for h in _RE_MD5.findall(text) if h.lower() not in sha1_set]
    result.md5 = _dedup(md5_matches)

    # IPv4
    ipv4_raw = _RE_IPV4.findall(text)
    if not include_private_ips:
        ipv4_raw = [ip for ip in ipv4_raw if not _is_private_ip(ip)]
    # Filter out likely version numbers (e.g., 1.0.0.0, 2.0.0.0)
    ipv4_raw = [ip for ip in ipv4_raw if not ip.endswith(".0.0")]
    result.ipv4 = _dedup(ipv4_raw)

    # IPv6
    result.ipv6 = _dedup(_RE_IPV6.findall(text))

    # URLs
    url_raw = _RE_URL.findall(text)
    # Clean trailing punctuation
    cleaned_urls = []
    for url in url_raw:
        url = url.rstrip(".,;:!?'\")")
        if len(url) > 10:  # Skip very short URLs
            cleaned_urls.append(url)
    result.urls = _dedup(cleaned_urls)

    # Email addresses
    result.emails = _dedup(_RE_EMAIL.findall(text))

    # Domains — extract but filter out noise
    domain_raw = _RE_DOMAIN.findall(text)
    # Filter: must have valid TLD, skip XML namespaces, skip already-captured emails
    email_domains = {e.split("@")[1].lower() for e in result.emails}
    url_domains = set()
    for url in result.urls:
        try:
            # Extract domain from URL
            after_scheme = url.split("://", 1)[-1]
            host = after_scheme.split("/")[0].split(":")[0].split("?")[0]
            url_domains.add(host.lower())
        except (IndexError, ValueError):
            pass

    filtered_domains = []
    for d in domain_raw:
        dl = d.lower()
        if dl in domain_skip:
            continue
        if dl in email_domains or dl in url_domains:
            continue  # Already captured via email or URL
        # Skip if it looks like a file extension pattern (e.g., "file.zip")
        parts = dl.split(".")
        if len(parts) == 2 and len(parts[0]) <= 3:
            continue
        filtered_domains.append(d)
    result.domains = _dedup(filtered_domains)

    # Passwords
    pw_matches = _RE_PASSWORD.findall(text)
    # Filter out very short or common words
    pw_filtered = [
        pw
        for pw in pw_matches
        if len(pw) >= 4 and pw.lower() not in {"the", "your", "this", "that", "with"}
    ]
    result.passwords = _dedup(pw_filtered)

    return result


# ------------------------------------------------------------------
# IOC merge and defang helpers
# ------------------------------------------------------------------


def merge_ioc_dicts(dicts: list[dict]) -> IOCResult:
    """Merge multiple IOC dicts (from ``IOCResult.to_dict()``) into one.

    Deduplicates values across all dicts while preserving first-seen order.
    """
    merged = IOCResult()
    for d in dicts:
        merged.ipv4.extend(d.get("ipv4", []))
        merged.ipv6.extend(d.get("ipv6", []))
        merged.urls.extend(d.get("urls", []))
        merged.emails.extend(d.get("emails", []))
        merged.domains.extend(d.get("domains", []))
        merged.md5.extend(d.get("md5", []))
        merged.sha1.extend(d.get("sha1", []))
        merged.sha256.extend(d.get("sha256", []))
        merged.passwords.extend(d.get("passwords", []))
    # Deduplicate
    merged.ipv4 = _dedup(merged.ipv4)
    merged.ipv6 = _dedup(merged.ipv6)
    merged.urls = _dedup(merged.urls)
    merged.emails = _dedup(merged.emails)
    merged.domains = _dedup(merged.domains)
    merged.md5 = _dedup(merged.md5)
    merged.sha1 = _dedup(merged.sha1)
    merged.sha256 = _dedup(merged.sha256)
    merged.passwords = _dedup(merged.passwords)
    return merged


def defang_ioc_data(data: dict) -> dict:
    """Return a copy of an IOC summary dict with all values defanged.

    Applies common defanging transformations:
    - ``http`` -> ``hxxp``
    - ``.`` in IPs/domains -> ``[.]``
    - ``@`` in emails -> ``[@]``
    """
    out: dict = {}
    for key, values in data.items():
        if not isinstance(values, list):
            out[key] = values
            continue
        defanged = []
        for v in values:
            v = str(v)
            if key in ("ipv4", "ipv6"):
                v = v.replace(".", "[.]")
            elif key == "domains":
                v = v.replace(".", "[.]")
            elif key == "urls":
                v = v.replace("http://", "hxxp://").replace("https://", "hxxps://")
                v = v.replace("ftp://", "fxp://")
            elif key == "emails":
                v = v.replace("@", "[@]")
            defanged.append(v)
        out[key] = defanged
    return out
