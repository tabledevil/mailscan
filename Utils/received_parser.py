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
    (r"(from\s+(?P<from_name>[\[\S\]]+)\s+\(((?P<from_hostname>[\S]*)|)\s*\[(IPv6\:(?P<from_ipv6>[a-f\d\:]+)\:|)((?P<from_ip>[\d\.\:]+)|)\]\s*(\(may\s+be\s+forged\)|)\)\s*(\(using\s+(?P<tls>[\w\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\([\w\/\s]+\)\)\s+(\(No\s+client\s+certificate\s+requested\)|)|)|)\s*(\(Authenticated\s+sender\:\s+(?P<authenticated_sender>[\w\.\-\@]+)\)|)\s*by\s+(?P<by_hostname>[\S]+)\s*(\((?P<by_hostname2>[\S]*)\s*\[((?P<by_ipv6>[a-f\:\d]+)|)(?P<by_ip>[\d\.]+)\]\)|)\s*(\([^\)]*\)|)\s*(\(Postfix\)|)\s*(with\s+(?P<protocol>\w*)|)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+\<(?P<envelope_for>[\w\.\@\-]+)\>|)", "postfix"),
    (r"(from\s+(?P<from_name>[\[\S\]]+)\s+\(((?P<from_hostname>[\S]*)|)\s*\[(IPv6\:(?P<from_ipv6>[a-f\d\:]+)|)\]\)\s*(\(using\s+(?P<tls>[\w\.]+)\s+with\s+cipher\s+(?P<cipher>[\w\-]+)\s+\([\w\/\s]+\)\)\s+(\(No\s+client\s+certificate\s+requested\)|)|)|)\s*(\(Authenticated\s+sender\:\s+(?P<authenticated_sender>[\w\.\-\@]+)\)|)\s*by\s+(?P<by_hostname>[\S]+)\s*(\((?P<by_hostname2>[\S]*)\s*\[((?P<by_ipv6>[a-f\:\d]+)|)(?P<by_ip>[\d\.]+)\]\)|)\s*(\([^\)]*\)|)\s*(\(Postfix\)|)\s*(with\s+(?P<protocol>\w+)|)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+\<(?P<envelope_for>[\w\.\@\-]+)\>|)", "postfix"),
    (r"\s*from\s+\[?(?P<from_ip>[\d\.\:]+)\]?\s*(\((port=\d+|)\s*helo=(?P<from_name>[\[\]\w\.\:\-]+)\)|)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s*(\((?P<cipher>[\w\.\:\_\-]+)\)|)\s*(\(Exim\s+(?P<exim_version>[\d\.\_]+)\)|)\s*\(envelope-from\s+<?(?P<envelope_from>[\w\@\-\.]*)>?\s*\)\s*id\s+(?P<id>[\w\-]+)\s*\s*(for\s+<?(?P<envelope_for>[\w\.\@\-]+)>?|)", "exim"),
    (r"\s*from\s+(?P<from_hostname>[\w\.]+)\s+\(\[?(?P<from_ip>[\d\.\:a-f]+)\]?(\:\d+|)\s*(helo\=\[?(?P<from_name>[\w\.\:\-]+)|)\]?\)\s+by\s+(?P<by_hostname>[\w\-\.]+)\s+with\s+(?P<protocol>\w+)\s+(\((?P<cipher>[\w\.\:\_]+)\)|)\s*\(Exim\s+(?P<exim_version>[\d\.\_]+)\)\s*\(envelope-from\s+\<(?P<envelope_from>[\w\@\-\.]+)\>\s*\)\s*id\s+(?P<id>[\w\-]+)\s*(for\s+(?P<envelope_for>[\w\.\@\-]+)|)", "exim"),
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
    (r"from\s+(?P<from_name>[\w\.\-]+)\s+\#?\s*(\(|\[|\(\[)\s*(?P<from_ip>[\d\.\:a-f]+)\s*(\]|\)|\]\))\s+by\s+(?P<by_hostname>[\w\.\-]+)(\s+\([\w\.\s\/]+\)|)\s*(with\s+(?P<protocol>\w+)|)\s*(id\s+(?P<id>[\w]+)|)(\(\-\)|)\s*(for\s+\<(?P<envelope_for>[\w\@\.\-]+)\>?|)", "unknown"),
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
    authenticated_sender: str = ""
    raw_header: str = ""  # original header text for forensic reference
    match_quality: int = 0  # number of non-empty extracted fields

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

    @property
    def is_internal(self) -> bool:
        """True if the from_ip is a private/loopback/link-local address."""
        ip = self.from_ip or self.from_ipv6
        if not ip:
            return False
        # IPv4 checks
        if ip.startswith("127.") or ip == "::1":
            return True
        if ip.startswith("10."):
            return True
        if ip.startswith("192.168."):
            return True
        # 172.16.0.0/12
        if ip.startswith("172."):
            try:
                second_octet = int(ip.split(".")[1])
                if 16 <= second_octet <= 31:
                    return True
            except (IndexError, ValueError):
                pass
        # IPv6 link-local
        if ip.lower().startswith("fe80:"):
            return True
        return False


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

    from_ip = matched_fields.get("from_ip", "")
    from_ipv6 = matched_fields.get("from_ipv6", "")
    # IPv6 normalization: if from_ip contains ':', move to from_ipv6
    if from_ip and ":" in from_ip and not from_ipv6:
        from_ipv6 = from_ip
        from_ip = ""
    by_ip = matched_fields.get("by_ip", "")

    quality = sum(1 for v in matched_fields.values() if v)

    return ReceivedHop(
        server_type=server_type,
        from_name=matched_fields.get("from_name", ""),
        from_hostname=matched_fields.get("from_hostname", ""),
        from_ip=from_ip,
        from_ipv6=from_ipv6,
        by_hostname=matched_fields.get("by_hostname", ""),
        by_ip=by_ip,
        protocol=matched_fields.get("protocol", ""),
        tls=matched_fields.get("tls", ""),
        cipher=matched_fields.get("cipher", ""),
        envelope_from=matched_fields.get("envelope_from", ""),
        envelope_for=matched_fields.get("envelope_for", ""),
        id=matched_fields.get("id", ""),
        authenticated_sender=matched_fields.get("authenticated_sender", ""),
        timestamp=timestamp,
        raw_fields=matched_fields,
        raw_header=header,
        match_quality=quality,
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


def _extract_tz_offset(timestamp) -> str:
    """Extract timezone offset string like '+0200' from a datetime."""
    if not timestamp or not timestamp.tzinfo:
        return ""
    try:
        offset = timestamp.utcoffset()
        if offset is None:
            return ""
        total_seconds = int(offset.total_seconds())
        sign = "+" if total_seconds >= 0 else "-"
        total_seconds = abs(total_seconds)
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60
        return f"{sign}{hours:02d}{minutes:02d}"
    except (TypeError, AttributeError):
        return ""


def _format_delta(total_seconds: int) -> str:
    """Format a delta in seconds to a compact human-readable string."""
    if total_seconds < 0:
        return f"{total_seconds}s SKEW"
    elif total_seconds < 60:
        return f"{total_seconds}s"
    elif total_seconds < 3600:
        return f"{total_seconds // 60}m{total_seconds % 60}s"
    else:
        hours = total_seconds // 3600
        mins = (total_seconds % 3600) // 60
        return f"{hours}h{mins}m"


def _compute_delta(t1, t2) -> int | None:
    """Compute seconds between two timestamps, UTC-normalized. Returns None on error."""
    from datetime import timezone as _tz
    try:
        a = t1.astimezone(_tz.utc) if t1.tzinfo else t1
        b = t2.astimezone(_tz.utc) if t2.tzinfo else t2
        return int((b - a).total_seconds())
    except (TypeError, AttributeError):
        return None


def build_hop_display_data(hops: list[ReceivedHop], gateway_findings: list[dict] | None = None, reverse: bool = True) -> list[dict]:
    """Build display-ready hop dicts with deltas, tz changes, gateway attachments.

    Args:
        hops: Parsed ReceivedHop list (newest-first from parse_received_headers)
        gateway_findings: List of dicts with keys: type, label, data (optional).
            type is one of: 'ironport', 'forefront', 'exchange_auth', 'mua', 'originating_ip'
        reverse: If True, reverse to oldest-first (delivery order)

    Returns:
        List of enriched hop dicts ready for renderers.
    """
    ordered = list(reversed(hops)) if reverse else list(hops)
    if not ordered:
        return []

    gateway_findings = gateway_findings or []

    # Pre-compute: find the last hop before a Microsoft EOP edge for IronPort placement
    eop_edge_idx = None
    for i, hop in enumerate(ordered):
        by_lower = hop.by_hostname.lower()
        if "mail.protection.outlook.com" in by_lower or "prod.outlook.com" in by_lower:
            eop_edge_idx = i
            break

    # Find the hop whose from_ip matches Forefront CIP
    forefront_items = [g for g in gateway_findings if g.get("type") == "forefront"]
    forefront_after_idx = {}
    for fg in forefront_items:
        cip = fg.get("data", {}).get("cip", "")
        if cip:
            for i, hop in enumerate(ordered):
                if hop.from_ip == cip:
                    forefront_after_idx[i] = fg
                    break

    # Build enriched hops
    result = []
    prev_tz = ""
    for i, hop in enumerate(ordered):
        tz_offset = _extract_tz_offset(hop.timestamp)

        # Compute delta from previous hop
        delta_seconds = None
        if i > 0 and hop.timestamp and ordered[i - 1].timestamp:
            delta_seconds = _compute_delta(ordered[i - 1].timestamp, hop.timestamp)

        # Build by display with IP
        by_str = hop.by_hostname or hop.by_ip or "?"
        by_ip = hop.by_ip or ""

        # Build from display with IP
        from_str = hop.from_name or hop.from_hostname or hop.from_ip or hop.from_ipv6 or "?"
        from_ip = hop.from_ip or hop.from_ipv6 or ""

        # Annotations
        annotations = []
        if hop.is_internal:
            annotations.append("internal")
        # Self-loop: from and by are the same host
        if from_str.lower().rstrip(".") == by_str.lower().rstrip("."):
            annotations.append("self-loop")

        tz_changed = bool(prev_tz and tz_offset and tz_offset != prev_tz)
        no_tls = not hop.has_tls and hop.from_display != "?" and "self-loop" not in annotations

        # Timestamp display
        ts_display = ""
        if hop.timestamp:
            ts_display = hop.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            if tz_offset:
                ts_display += f" {tz_offset}"

        # Inferred hops to show after this hop
        inferred_after = []

        # IronPort: show after last hop before EOP edge
        if eop_edge_idx is not None and i == eop_edge_idx - 1:
            for g in gateway_findings:
                if g.get("type") == "ironport":
                    inferred_after.append(g)

        # Forefront: show after matching hop
        if i in forefront_after_idx:
            inferred_after.append(forefront_after_idx[i])

        hop_dict = {
            "hop": i + 1,
            "by_hostname": by_str,
            "by_ip": by_ip,
            "from_name": from_str,
            "from_ip": from_ip,
            "protocol": hop.protocol or "",
            "tls": hop.tls or "",
            "cipher": hop.cipher or "",
            "server_type": hop.server_type if hop.server_type and hop.server_type != "unknown" else "",
            "timestamp": ts_display,
            "delta_seconds": delta_seconds,
            "delta_display": _format_delta(delta_seconds) if delta_seconds is not None else "",
            "tz_offset": tz_offset,
            "tz_changed": tz_changed,
            "prev_tz": prev_tz if tz_changed else "",
            "no_tls": no_tls,
            "is_internal": hop.is_internal,
            "annotations": annotations,
            "authenticated_sender": hop.authenticated_sender or "",
            "inferred_after": inferred_after,
        }
        result.append(hop_dict)

        if tz_offset:
            prev_tz = tz_offset

    # Attach MUA as a special footer entry
    mua_items = [g for g in gateway_findings if g.get("type") == "mua"]
    origip_items = [g for g in gateway_findings if g.get("type") == "originating_ip"]
    exchange_items = [g for g in gateway_findings if g.get("type") == "exchange_auth"]

    # Attach any remaining gateway items not already placed
    placed_types = {"ironport", "forefront", "mua", "originating_ip", "exchange_auth"}
    remaining = [g for g in gateway_findings if g.get("type") not in placed_types]
    if remaining and result:
        result[-1]["inferred_after"].extend(remaining)

    # Store footer items for renderers
    if result:
        footer = []
        for m in mua_items:
            footer.append(m)
        for o in origip_items:
            footer.append(o)
        for e in exchange_items:
            footer.append(e)
        if footer:
            result[-1].setdefault("footer", [])
            result[-1]["footer"] = footer

    return result


def format_mail_route(hops: list[ReceivedHop], reverse: bool = True) -> str:
    """Format parsed hops into a compact one-line-per-hop fallback string.

    This is the plain-text fallback used in Report.text for non-hop-aware renderers.

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
        # Build hop line with IP details
        from_str = hop.from_display
        if hop.from_ip and hop.from_ip != from_str:
            from_str += f" [{hop.from_ip}]"
        elif hop.from_ipv6 and hop.from_ipv6 != from_str:
            from_str += f" [{hop.from_ipv6}]"

        by_str = hop.by_display
        if hop.by_ip and hop.by_ip != by_str:
            by_str += f" [{hop.by_ip}]"

        proto = f" ({hop.protocol})" if hop.protocol else ""
        tls_info = ""
        if hop.tls:
            tls_info = f" TLS:{hop.tls}"
        elif hop.cipher:
            tls_info = f" cipher:{hop.cipher}"

        server = f" [{hop.server_type}]" if hop.server_type and hop.server_type != "unknown" else ""
        auth = f" AUTH:{hop.authenticated_sender}" if hop.authenticated_sender else ""
        internal = " (internal)" if hop.is_internal else ""

        line = f"  {i + 1}. {from_str} -> {by_str}{proto}{tls_info}{server}{auth}{internal}"

        # Latency calculation (UTC-normalized)
        if i + 1 < len(ordered) and hop.timestamp and ordered[i + 1].timestamp:
            delta = _compute_delta(hop.timestamp, ordered[i + 1].timestamp)
            if delta is not None:
                line += f"  ({_format_delta(delta)})"

        # Timestamp
        if hop.timestamp:
            line += f"  [{hop.timestamp}]"

        lines.append(line)

    return "\n".join(lines)


def check_chain_continuity(hops: list[ReceivedHop], reverse: bool = True) -> list[dict]:
    """Check if the hop chain is continuous (each hop's 'by' matches the next hop's 'from').

    Returns a list of chain break descriptions.
    """
    ordered = list(reversed(hops)) if reverse else list(hops)
    breaks = []

    for i in range(len(ordered) - 1):
        current_by = ordered[i].by_hostname.lower().rstrip(".")
        next_from_name = ordered[i + 1].from_name.lower().rstrip(".")
        next_from_hostname = ordered[i + 1].from_hostname.lower().rstrip(".")
        next_from_ip = ordered[i + 1].from_ip
        current_by_ip = ordered[i].by_ip

        # Check if next hop's from matches current hop's by
        match = False
        if current_by and (current_by == next_from_name or current_by == next_from_hostname):
            match = True
        # Check if IPs match when hostnames differ (same host, different DNS names)
        elif current_by_ip and (current_by_ip == next_from_ip):
            match = True
        # Check if hostnames share a common base (e.g., AMS1EPF0000008E.mail.protection.outlook.com vs AMS1EPF0000008E.eurprd05.prod.outlook.com)
        elif current_by and next_from_name:
            current_parts = current_by.split(".")
            next_parts = next_from_name.split(".")
            if current_parts and next_parts and current_parts[0] == next_parts[0]:
                match = True

        if not match:
            breaks.append({
                "after_hop": i + 1,
                "before_hop": i + 2,
                "from_by": ordered[i].by_hostname or ordered[i].by_ip,
                "to_from": ordered[i + 1].from_display,
                "description": f"Chain break between hop {i+1} ({ordered[i].by_display}) and hop {i+2} ({ordered[i+1].from_display})"
            })

    return breaks


def detect_latency_anomalies(hops: list[ReceivedHop], reverse: bool = True) -> list[dict]:
    """Detect timing anomalies in the hop chain."""
    ordered = list(reversed(hops)) if reverse else list(hops)
    anomalies = []

    for i in range(len(ordered) - 1):
        if not ordered[i].timestamp or not ordered[i + 1].timestamp:
            continue
        try:
            from datetime import timezone as _tz
            t1 = ordered[i].timestamp.astimezone(_tz.utc) if ordered[i].timestamp.tzinfo else ordered[i].timestamp
            t2 = ordered[i + 1].timestamp.astimezone(_tz.utc) if ordered[i + 1].timestamp.tzinfo else ordered[i + 1].timestamp
            delta_seconds = int((t2 - t1).total_seconds())

            if delta_seconds < -300:  # > 5 min negative
                anomalies.append({
                    "type": "possible_forgery",
                    "hop": i + 1,
                    "delta_seconds": delta_seconds,
                    "description": f"Hop {i+1} -> {i+2}: {delta_seconds}s (large negative delta — possible header forgery)"
                })
            elif delta_seconds < -5:  # minor clock skew
                anomalies.append({
                    "type": "clock_skew",
                    "hop": i + 1,
                    "delta_seconds": delta_seconds,
                    "description": f"Hop {i+1} -> {i+2}: {delta_seconds}s clock skew"
                })
            elif delta_seconds > 86400:  # > 24h
                anomalies.append({
                    "type": "long_delay",
                    "hop": i + 1,
                    "delta_seconds": delta_seconds,
                    "description": f"Hop {i+1} -> {i+2}: {delta_seconds//3600}h delay (queued/held message)"
                })
        except (TypeError, AttributeError):
            pass

    return anomalies


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
