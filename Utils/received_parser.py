"""Received header parser for email hop reconstruction.

Extracted from eml.py — parses the highly variable ``Received:`` headers
from emails to reconstruct the mail delivery route with hops, latencies,
server types, IPs, TLS info, and timestamps.

Covers 20+ mail server formats: MS SMTP, Postfix, Exim, Oracle, ASSP,
ecelerity, Nemesis, qmail, CommuniGate, SquirrelMail, Sendmail,
Sun Java, Axigen, Horde, PGP, Sophos, and generic/unknown patterns.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("matt")

try:
    from dateutil.parser import parse as parse_date
except ImportError:
    parse_date = None


class ReceivedParserError(Exception):
    """Raised when a Received header cannot be parsed."""

    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


# fmt: off
# Each entry: (regex_pattern, server_type_label[, optional_extra])
# Regexes are tried in order — most specific first.
RECEIVED_REGEXES = [
    (r"from\s+(mail\s+pickup\s+service|(?P<from_name>[\[\]\w\.\-]*))\s*(\(\s*\[?(?P<from_ip>[a-f\d\.\:]+)(\%\d+|)\]?\s*\)|)\s*by\s*(?P<by_hostname>[\w\.\-]+)\s*(\(\s*\[?(?P<by_ip>[\d\.\:a-f]+)(\%\d+|)\]?\)|)\s*(over\s+TLS\s+secured\s+channel|)\s*with\s*(mapi|Microsoft\s+SMTP\s+Server|Microsoft\s+SMTPSVC(\((?P<server_version>[\d\.]+)\)|))\s*(\((TLS|version=(?P<tls>[\w\.]+)|)\,?\s*(cipher=(?P<cipher>[\w\_]+)|)\)|)\s*(id\s+(?P<id>[\d\.]+)|)", "MS SMTP Server"),
    (r"(from\s+(?P<from_name>[\[\S\]]+)\s+\(((?P<from_hostname>[\S]*)|)\s*\[(IPv6\:(?P<from_ipv6>[a-f\d\:]+)\:|)((?P<from_ip>[\d\.\:]+)|)\]\s*(\(may\s+be\s+forged\)|)\)\s*(\(using\s+(?P<tls>[\w\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\([\w\/\s]+\)\)\s+(\(No\s+client\s+certificate\s+requested\)|)|)|)\s*(\(Authenticated\s+sender\:\s+(?P<authenticated_sender>[\w\.\-\@]+)\)|)\s*by\s+(?P<by_hostname>[\S]+)\s*(\((?P<by_hostname2>[\S]*)\s*\[((?P<by_ipv6>[a-f\:\d]+)|)(?P<by_ip>[\d\.]+)\]\)|)\s*(\([^\)]*\)|)\s*(\(Postfix\)|)\s*(with\s+(?P<protocol>\w*)|)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+\<(?P<envelope_for>[\w\.\@]+)\>|)", "postfix"),
    (r"(from\s+(?P<from_name>[\[\S\]]+)\s+\(((?P<from_hostname>[\S]*)|)\s*\[(IPv6\:(?P<from_ipv6>[a-f\d\:]+)|)\]\)\s*(\(using\s+(?P<tls>[\w\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\([\w\/\s]+\)\)\s+(\(No\s+client\s+certificate\s+requested\)|)|)|)\s*(\(Authenticated\s+sender\:\s+(?P<authenticated_sender>[\w\.\-\@]+)\)|)\s*by\s+(?P<by_hostname>[\S]+)\s*(\((?P<by_hostname2>[\S]*)\s*\[((?P<by_ipv6>[a-f\:\d]+)|)(?P<by_ip>[\d\.]+)\]\)|)\s*(\([^\)]*\)|)\s*(\(Postfix\)|)\s*(with\s+(?P<protocol>\w+)|)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+\<(?P<envelope_for>[\w\.\@]+)\>|)", "postfix"),
    (r"\s*from\s+\[?(?P<from_ip>[\d\.\:]+)\]?\s*(\((port=\d+|)\s*helo=(?P<from_name>[\[\]\w\.\:\-]+)\)|)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s*(\((?P<cipher>[\w\.\:\_\-]+)\)|)\s*(\(Exim\s+(?P<exim_version>[\d\.\_]+)\)|)\s*\(envelope-from\s+<?(?P<envelope_from>[\w\@\-\.]*)>?\s*\)\s*id\s+(?P<id>[\w\-]+)\s*\s*(for\s+<?(?P<envelope_for>[\w\.\@]+)>?|)", "exim"),
    (r"\s*from\s+(?P<from_hostname>[\w\.]+)\s+\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?(\:\d+|)\s*(helo\=\[?(?P<from_name>[\w\.\:\-]+)|)\]?\)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s+(\((?P<cipher>[\w\.\:\_]+)\)|)\s*\(Exim\s+(?P<exim_version>[\d\.\_]+)\)\s*\(envelope-from\s+\<(?P<envelope_from>[\w\@\-\.]+)\>\s*\)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+(?P<envelope_for>[\w\.\@]+)|)", "exim"),
    (r"from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(Exim\s+(?P<version>[\d\.]+)\)\s+\(envelope-from\s+<*(?P<envelope_from>[\w\.\-\@]+)>*\)\s+id\s+(?P<id>[\w\.\-]+)\s+for\s+<?(?P<envelope_for>[\w\.\-\@]+)>?", "exim"),
    (r"from\s+(?P<from_name>[\[\]\w\-\.]+)\s+\(((?P<from_hostname>[\w\.\-]+)|)\s*\[(?P<from_ip>[\da-f\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Oracle\s+Communications\s+Messaging\s+Server\s+(?P<oracle_version>[\w\.\-]+)(\([\d\.]+\)|)\s+(32bit|64bit|)\s*(\([^\)]+\)|)\)\s*with\s+(?P<protocol>\w+)\s+id\s+\<?(?P<id>[\w\@\.\-]+)\>?", "Oracle Communication Messaging Server"),
    (r"from\s+(?P<from_hostname>[\w\-\.]+)\s+\(\[(?P<from_ip>[\d\.\:a-f]+)\]\s+helo=(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(ASSP\s+(?P<assp_version>[\d\.]+)\s*\)", "ASSP"),
    (r"from\s+(?P<from_hostname>[\[\]\d\w\.\-]+)\s+\(\[\[?(?P<from_ip>[\d\.]+)(\:\d+|)\]\s*(helo=(?P<from_name>[\w\.\-]+)|)\s*\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(envelope-from\s+\<?(?P<envelope_from>[^>]+)\>?\)\s+\(ecelerity\s+(?P<version>[\d\.]+)\s+r\([\w\-\:\.]+\)\)\s+with\s+(?P<protocol>\w+)\s*(\(cipher=(?P<cipher>[\w\-\_]+)\)|)\s*id\s+(?P<id>[\.\-\w\/]+)", "ecelerity"),
    (r"from\s+(?P<from_name>[\[\]\w\.\-]+)\s+\(((?P<from_hostname>[\w\.\-]+)|)\s*(\[(?P<from_ip>[\d\.\:a-f]+)\]|)\)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+([\w\.\-\=]+\)|)\s+with\s+(?P<protocol>\w+)\s+\(Nemesis\)\s+id\s+(?P<id>[\w\.\-]+)\s*(for\s+\<?(?P<envelope_for>[\w\.\@\-]+)\>?|)", "nemesis"),
    (r"\(qmail\s+\d+\s+invoked\s+(from\s+network|)(by\s+uid\s+\d+|)\)", "qmail"),
    (r"from\s+\[?(?P<from_ip>[\d\.a-f\:]+)\]?\s+\(account\s+<?(?P<envelope_from>[\w\.\@\-]+)>?\s+HELO\s+(?P<from_name>[\w\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]*)\s+\(CommuniGate\s+Pro\s+SMTP\s+(?P<version>[\d\.]+)\)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\-\.]+)\s+for\s+<?(?P<envelope_for>[\w\.\-\@]+)>?", "CommuniGate"),
    (r"from\s+(?P<from_ip>[\d\.\:a-f]+)\s+\(SquirrelMail\s+authenticated\s+user\s+(?P<envelope_from>[\w\@\.\-]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)", "SquirrelMail"),
    (r"by\s+(?P<by_hostname>[\w\.\-]+)\s+\((?P<protocol>\w+)\s+sendmail\s*(emulation|)\)", "sendmail"),
    (r"from\s+(?P<from_name>[\[\]\w\.\-]+)\s+\(\[(?P<from_hostname>[\w\.\-]+)\]\s+\[(?P<from_ip>[\d\.a-f\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Sun\s+Java\(tm\)\s+System\s+Messaging\s+Server\s+(?P<version>[\w\.\-]+)\s+\d+bit\s+\(built\s+\w+\s+\d+\s+\d+\)\)\s+with\s+(?P<protocol>\w+)\s+id\s+<?(?P<id>[\w\.\-\@]+)>?", "Sun Java System Messaging Server"),
    (r"from\s+(?P<from_name>[\w\.\-\[\]]+)\s+\((?P<from_ip>[\d\.a-f\:]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Axigen\)\s+with\s+(?P<protocol>\w+)\s+id\s+(?P<id>[\w\.\-]+)", "Axigen"),
    (r"from\s+(?P<from_name>[\w\.\-]+)\s+\((?P<from_hostname>[\w\.\-]+)\s+\[(?P<from_ip>[\d\.a-f\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(Horde\s+MIME\s+library\)\s+with\s+(?P<protocol>\w+)", "Horde MIME library"),
    (r"from\s+(?P<from_name>[\w\.\-\[\]]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(PGP\s+Universal\s+Service\)", "PGP Universal Service"),
    (r"from\s+(?P<from_name>[\w\.\-]+)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)\s+\(Sophos\s+PureMessage\s+Version\s+(?P<version>[\d\.\-]+)\)\s+id\s+(?P<id>[\w\.\-]+)\s+for\s+(?P<envelope_for>[\w\.\-\@]+)", "Sophos PureMessage"),
    (r"by\s+(?P<by_ip>[\d\.\:a-f]+)\s+with\s+(?P<protocol>\w+)", "unknown"),
    (r"from\s+(?P<from_name>[\w\.\-]+)\s+\#?\s*(\(|\[|\(\[)\s*(?P<from_ip>[\d\.\:a-f]+)\s*(\]|\)|\]\))\s+by\s+(?P<by_hostname>[\w\.\-]+)(\s+\([\w\.\s\/]+\)|)\s*(with\s+(?P<protocol>\w+)|)\s*(id\s+(?P<id>[\w]+)|)(\(\-\)|)\s*(for\s+\<(?P<envelope_for>[\w\@\.]+)\>?|)", "unknown"),
    (r"from\s+(?P<from_hostname>[\w\.\-]+)\s*\(HELO\s+(?P<from_name>[\w\.\-]+)\)\s*\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?\)\s+by\s+(?P<by_hostname>[\w\.\-]+)(\s+\([\d\.]+\)|)\s*(with\s+(?P<protocol>\w+)|)\s*(id\s+(?P<id>[\w]+)|)(\(\-\)|)", "unknown"),
    (r"from\s+(\([\(\[](?P<from_ip>[\d\.\:a-f]+)[\)\]]|)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+id\s+(?P<id>\w+)\s*(with\s+(?P<protocol>\w+)|)\s*\s*(for\s+\<(?P<envelope_for>[\w\@\.\-]+)\>|)", "unknown"),
    (r"from\s+(?P<from_hostname>[\w\.]+)\s+(\(HELO\s+(?P<from_name>[\w\.\-]+)\)|)\s*(\((?P<from_ip>[\da-f\.\:]+)\)|)\s*by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<cipher>[\w\-]+)\s+encrypted\s+SMTP", "unknown"),
    (r"from\s+(?P<from_hostname>[\w\.\-]+)\s+(\(HELO\s+(?P<from_name>[\w\.\-]+)\)|)\s+\((?P<envelope_from>[\w\.]+\@[\w\.]+)\@(?P<from_ip>[\da-d\.\:]+)\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+with\s+(?P<protocol>\w+)", "unknown"),
    (r"from\s+(?P<from_hostname>[\w\.\-]+)\s+\(HELO\s+(?P<from_name>[\w\.\-\?]+)\)\s+\(\w+\@[\w\.]+\@(?P<from_ip>[\d\.a-f\-]+)_\w+\)\s+by\s+(?P<by_hostname>[\w\.\-\:]+)\s+with\s+(?P<protocol>\w+)", "unknown"),
    (r"from\s+(?P<from_name>[\w\.\-\[\]]+)\s+\(\[(?P<from_ip>[\da-f\.\:]+)\]\)\s+by\s+(?P<by_hostname>[\w\.\-]+)\s+\(\[(?P<by_ip>[\d\.a-f\:]+)\]\)\s+with\s+(?P<protocol>\w+)", "unknown"),
    (r"from\s+(?P<from_name>[\w\.\-\[\]]+)\s+(\[(?P<from_ip>[\da-f\.\:]+)\]\s+)?by\s+(?P<by_hostname>[\w\.\-]+)\s+(\[(?P<by_ip>[\d\.a-f\:]+)\]\s+)?with\s+(?P<protocol>\w+)\s+id\s+(?P<id>\w+)\s+(\(using\s+(?P<cipher>([\w\-\_. ]+|(\([^()]+\)))+)?)", "unknown"),
]
# fmt: on


@dataclass
class ReceivedHop:
    """Parsed result of a single Received header."""

    server_type: str = ""
    from_name: str = ""
    from_hostname: str = ""
    from_ip: str = ""
    from_ipv6: str = ""
    by_hostname: str = ""
    by_ip: str = ""
    protocol: str = ""
    tls: str = ""
    cipher: str = ""
    envelope_from: str = ""
    envelope_for: str = ""
    id: str = ""
    timestamp: Optional[object] = None  # datetime or None
    raw_fields: dict = field(default_factory=dict)

    @property
    def from_display(self) -> str:
        """Human-readable source identifier."""
        return self.from_name or self.from_hostname or self.from_ip or self.from_ipv6 or "?"

    @property
    def by_display(self) -> str:
        """Human-readable destination identifier."""
        return self.by_hostname or self.by_ip or "?"

    @property
    def has_tls(self) -> bool:
        return bool(self.tls or self.cipher)


def parse_received(header: str) -> ReceivedHop:
    """Parse a single ``Received:`` header string into a ReceivedHop.

    Raises ``ReceivedParserError`` if the header cannot be parsed.
    """
    # Separate timestamp after the ";"
    parts = header.split(";")
    if len(parts) < 2:
        raise ReceivedParserError("Invalid format: no timestamp separator ';'")

    # Parse timestamp
    timestamp = None
    if parse_date is not None:
        ts_part = parts[1]
        # Some headers have envelope info after the ;
        if "envelope" in ts_part:
            ts_part = ts_part.split("(")[0]
        ts_part = ts_part.replace("\n", "").strip()
        try:
            timestamp = parse_date(ts_part)
        except (ValueError, TypeError):
            log.debug(f"Could not parse timestamp: {ts_part!r}")

    # Try regexes on the routing part (before the ;)
    routing = parts[0]
    server_type = ""
    matched_fields = {}

    for regex_entry in RECEIVED_REGEXES:
        pattern = regex_entry[0]
        label = regex_entry[1]
        match = re.match(pattern, routing, re.IGNORECASE)
        if match:
            server_type = label
            matched_fields = {k: v for k, v in match.groupdict().items() if v}
            break
    else:
        raise ReceivedParserError("Unknown header format")

    return ReceivedHop(
        server_type=server_type,
        from_name=matched_fields.get("from_name", ""),
        from_hostname=matched_fields.get("from_hostname", ""),
        from_ip=matched_fields.get("from_ip", ""),
        from_ipv6=matched_fields.get("from_ipv6", ""),
        by_hostname=matched_fields.get("by_hostname", ""),
        by_ip=matched_fields.get("by_ip", ""),
        protocol=matched_fields.get("protocol", ""),
        tls=matched_fields.get("tls", ""),
        cipher=matched_fields.get("cipher", ""),
        envelope_from=matched_fields.get("envelope_from", ""),
        envelope_for=matched_fields.get("envelope_for", ""),
        id=matched_fields.get("id", ""),
        timestamp=timestamp,
        raw_fields=matched_fields,
    )


def parse_received_headers(headers: list[str]) -> list[ReceivedHop]:
    """Parse a list of Received header values, returning parsed hops.

    Unparseable headers are silently skipped (logged at DEBUG level).
    Returns hops in *original* order (newest first, as they appear in the email).
    """
    hops = []
    for header in headers:
        try:
            hop = parse_received(header)
            hops.append(hop)
        except ReceivedParserError as e:
            log.debug(f"Skipping unparseable Received header: {e}")
    return hops


def format_mail_route(hops: list[ReceivedHop], reverse: bool = True) -> str:
    """Format parsed hops into a human-readable mail route string.

    Args:
        hops: Parsed ReceivedHop list (newest-first, as returned by parse_received_headers)
        reverse: If True (default), reverse to show oldest-first (actual delivery order)

    Returns:
        Multi-line string showing the mail delivery path with hop numbers,
        server types, protocols, TLS info, and latencies.
    """
    ordered = list(reversed(hops)) if reverse else list(hops)
    if not ordered:
        return "No mail route information available"

    lines = []
    for i, hop in enumerate(ordered):
        # Build hop line
        from_str = hop.from_display
        by_str = hop.by_display
        proto = f" ({hop.protocol})" if hop.protocol else ""
        tls_info = ""
        if hop.tls:
            tls_info = f" TLS:{hop.tls}"
        elif hop.cipher:
            tls_info = f" cipher:{hop.cipher}"

        server = f" [{hop.server_type}]" if hop.server_type and hop.server_type != "unknown" else ""

        line = f"  {i + 1}. {from_str} -> {by_str}{proto}{tls_info}{server}"

        # Latency calculation
        if i + 1 < len(ordered) and hop.timestamp and ordered[i + 1].timestamp:
            try:
                delta = ordered[i + 1].timestamp - hop.timestamp
                line += f"  (+{delta})"
            except (TypeError, AttributeError):
                pass

        # Timestamp
        if hop.timestamp:
            line += f"  [{hop.timestamp}]"

        lines.append(line)

    return "Mail Route:\n" + "\n".join(lines)


def parse_auth_results(header: str) -> dict:
    """Parse an Authentication-Results header (RFC 7601).

    Returns a dict with keys like 'spf', 'dkim', 'dmarc' each containing
    their result (pass, fail, none, etc.) and optional details.

    This is a lightweight offline parser — it reads cached results from
    the Authentication-Results header rather than performing actual lookups.
    """
    results = {}

    # Extract the authserv-id (first token before ;)
    parts = header.split(";")
    if parts:
        results["authserv_id"] = parts[0].strip()

    # Parse method=result pairs
    # Patterns like: spf=pass, dkim=pass, dmarc=pass
    for method in ("spf", "dkim", "dmarc", "arc", "iprev"):
        pattern = rf"{method}\s*=\s*(\w+)"
        match = re.search(pattern, header, re.IGNORECASE)
        if match:
            result_value = match.group(1).lower()
            results[method] = result_value

            # Try to extract reason/details
            # e.g., spf=pass (sender IP is 1.2.3.4) smtp.mailfrom=x@y.com
            detail_pattern = rf"{method}\s*=\s*\w+\s*(\([^)]+\))?"
            detail_match = re.search(detail_pattern, header, re.IGNORECASE)
            if detail_match and detail_match.group(1):
                results[f"{method}_detail"] = detail_match.group(1).strip("()")

    # Extract header.from for DMARC alignment check
    header_from_match = re.search(r"header\.from\s*=\s*([\w\.\-\@]+)", header, re.IGNORECASE)
    if header_from_match:
        results["header_from"] = header_from_match.group(1)

    # Extract smtp.mailfrom for SPF
    smtp_from_match = re.search(r"smtp\.mailfrom\s*=\s*([\w\.\-\@]+)", header, re.IGNORECASE)
    if smtp_from_match:
        results["smtp_mailfrom"] = smtp_from_match.group(1)

    # Extract DKIM domain (header.d)
    dkim_domain_match = re.search(r"header\.d\s*=\s*([\w\.\-]+)", header, re.IGNORECASE)
    if dkim_domain_match:
        results["dkim_domain"] = dkim_domain_match.group(1)

    return results
