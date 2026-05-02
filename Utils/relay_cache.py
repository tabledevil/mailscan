"""Mail-relay annotation cache.

Two-layer system:

  1. **Static rules** — well-known relay/gateway patterns (Microsoft 365,
     Google, AWS SES, Mimecast, Proofpoint, …). Matches the receiving
     hostname against known suffixes. No I/O, no network.

  2. **Persistent JSON cache** at ``~/.matt/relay_cache.json`` — records
     first-seen / last-seen timestamps for hostnames the user has
     encountered, plus any user-supplied custom labels. Read once per
     process; written when new entries are added.

The cache is offline-first: there are no DNS / WHOIS / ASN lookups. The
goal is to give the analyst orientation ("this hop is M365") without
hidden network traffic.

API:

    RelayCache.annotate(hostname, ip="") -> list[str]
        Returns annotation labels for this host, e.g. ["microsoft-365"].

    RelayCache.observe(hostname, ip="")
        Record a sighting (updates last_seen).

    RelayCache.label(hostname, label)
        Manually attach a custom label (persisted).
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from typing import Iterable

log = logging.getLogger("matt")


# ---------------------------------------------------------------
# Static well-known-relay rules
# ---------------------------------------------------------------
# Each rule: (suffix-or-regex, label, severity-hint)
# The label is what gets surfaced to the analyst; severity-hint helps
# downstream renderers tint the row (currently unused — annotations are
# informational only).

_KNOWN_RELAYS: list[tuple[re.Pattern[str], str]] = [
    # Microsoft 365 / Exchange Online
    (re.compile(r"\.protection\.outlook\.com$", re.I), "microsoft-365 (EOP)"),
    (re.compile(r"\.eo\.outlook\.com$", re.I), "microsoft-365"),
    (re.compile(r"\.outlook\.com$", re.I), "microsoft-365"),
    (re.compile(r"\.prod\.outlook\.com$", re.I), "microsoft-365"),
    (re.compile(r"\.outlook\.office365\.com$", re.I), "microsoft-365"),
    (re.compile(r"\.office365\.com$", re.I), "microsoft-365"),
    # Google Workspace / Gmail
    (re.compile(r"\.google\.com$", re.I), "google"),
    (re.compile(r"^mail-[\w-]+\.google\.com$", re.I), "google"),
    (re.compile(r"\.googlemail\.com$", re.I), "google"),
    (re.compile(r"\.gmail\.com$", re.I), "google"),
    # AWS SES
    (re.compile(r"\.amazonses\.com$", re.I), "aws-ses"),
    (re.compile(r"\.amazonaws\.com$", re.I), "aws"),
    # Common MX gateway vendors
    (re.compile(r"\.mimecast\.com$", re.I), "mimecast"),
    (re.compile(r"\.mimecast-offshore\.com$", re.I), "mimecast"),
    (re.compile(r"\.pphosted\.com$", re.I), "proofpoint"),
    (re.compile(r"\.proofpoint\.com$", re.I), "proofpoint"),
    (re.compile(r"\.messagelabs\.com$", re.I), "symantec-messagelabs"),
    (re.compile(r"\.barracudanetworks\.com$", re.I), "barracuda"),
    (re.compile(r"\.iphmx\.com$", re.I), "cisco-ironport"),
    (re.compile(r"\.cisco\.com$", re.I), "cisco"),
    (re.compile(r"\.trendmicro\.com$", re.I), "trend-micro"),
    (re.compile(r"\.fireeye\.com$", re.I), "fireeye"),
    (re.compile(r"\.appriver\.com$", re.I), "appriver"),
    # ESPs / transactional senders
    (re.compile(r"\.mailgun\.org$", re.I), "mailgun"),
    (re.compile(r"\.sendgrid\.net$", re.I), "sendgrid"),
    (re.compile(r"\.mandrillapp\.com$", re.I), "mandrill"),
    (re.compile(r"\.mailchimp\.com$", re.I), "mailchimp"),
    (re.compile(r"\.sparkpostmail\.com$", re.I), "sparkpost"),
    (re.compile(r"\.postmarkapp\.com$", re.I), "postmark"),
]


def _match_static(hostname: str) -> list[str]:
    """Return labels matching the static rules for *hostname*."""
    if not hostname:
        return []
    host = hostname.strip().rstrip(".").lower()
    out: list[str] = []
    for pattern, label in _KNOWN_RELAYS:
        if pattern.search(host):
            if label not in out:
                out.append(label)
    return out


# ---------------------------------------------------------------
# Persistent cache
# ---------------------------------------------------------------


def _default_cache_path() -> str:
    override = os.environ.get("MATT_RELAY_CACHE")
    if override:
        return override
    home = os.path.expanduser("~")
    return os.path.join(home, ".matt", "relay_cache.json")


class _CacheState:
    def __init__(self):
        self.path: str = _default_cache_path()
        self.entries: dict[str, dict] = {}
        self.loaded: bool = False
        self.lock = threading.Lock()

    def reset(self, path: str | None = None) -> None:
        with self.lock:
            self.path = path or _default_cache_path()
            self.entries = {}
            self.loaded = False

    def ensure_loaded(self) -> None:
        if self.loaded:
            return
        with self.lock:
            if self.loaded:
                return
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.entries = json.load(f) or {}
            except FileNotFoundError:
                self.entries = {}
            except (OSError, json.JSONDecodeError) as e:
                log.debug("relay_cache: ignoring unreadable cache %s: %s", self.path, e)
                self.entries = {}
            self.loaded = True

    def flush(self) -> None:
        if not self.loaded:
            return
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
        except OSError as e:
            log.debug("relay_cache: cannot create dir for %s: %s", self.path, e)
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.entries, f, indent=2, sort_keys=True)
            os.replace(tmp, self.path)
        except OSError as e:
            log.debug("relay_cache: write failed for %s: %s", self.path, e)


_state = _CacheState()


class RelayCache:
    """Static + persistent relay annotations."""

    @staticmethod
    def reset(path: str | None = None) -> None:
        """Reset state (mainly for tests). Optionally point at a different
        cache file path."""
        _state.reset(path)

    @staticmethod
    def annotate(hostname: str, ip: str = "") -> list[str]:
        """Return annotation labels for *hostname*. Cheap; safe to call per-hop."""
        labels = _match_static(hostname)
        # Augment with persisted user-applied labels
        _state.ensure_loaded()
        host = (hostname or "").strip().rstrip(".").lower()
        if host and host in _state.entries:
            for lab in _state.entries[host].get("labels", []):
                if lab not in labels:
                    labels.append(lab)
        return labels

    @staticmethod
    def observe(hostname: str, ip: str = "") -> None:
        """Record a sighting of *hostname*. Updates first_seen / last_seen
        and persists to disk."""
        host = (hostname or "").strip().rstrip(".").lower()
        if not host:
            return
        _state.ensure_loaded()
        now = int(time.time())
        with _state.lock:
            entry = _state.entries.setdefault(
                host,
                {"first_seen": now, "last_seen": now, "ips": [], "labels": []},
            )
            entry["last_seen"] = now
            if ip and ip not in entry["ips"]:
                entry["ips"].append(ip)
        _state.flush()

    @staticmethod
    def label(hostname: str, label: str) -> None:
        """Attach a manual label to *hostname* and persist."""
        host = (hostname or "").strip().rstrip(".").lower()
        if not host or not label:
            return
        _state.ensure_loaded()
        with _state.lock:
            entry = _state.entries.setdefault(
                host,
                {"first_seen": int(time.time()), "last_seen": int(time.time()),
                 "ips": [], "labels": []},
            )
            if label not in entry["labels"]:
                entry["labels"].append(label)
        _state.flush()

    @staticmethod
    def all_entries() -> dict[str, dict]:
        """Return a snapshot of the persisted cache (for tests/diagnostics)."""
        _state.ensure_loaded()
        return dict(_state.entries)
