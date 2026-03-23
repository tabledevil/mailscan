"""Shared advanced analysis helpers for cross-cutting Sprint 5 features."""

from __future__ import annotations

import functools
import json
import logging
import math
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib import error as urlerror
from urllib import request as urlrequest

from Config.config import flags

log = logging.getLogger("matt")

try:
    import yara
except ImportError:
    yara = None

try:
    import ssdeep
except ImportError:
    ssdeep = None

try:
    import tlsh
except ImportError:
    tlsh = None

try:
    from dateutil.parser import parse as parse_date
except ImportError:
    parse_date = None


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def block_entropy(data: bytes, num_blocks: int = 64) -> list[float]:
    """Compute Shannon entropy for each block of data.

    Returns a list of entropy values (0.0-8.0), one per block.
    Useful for visualizing entropy distribution across a file.
    """
    if not data or num_blocks < 1:
        return []
    block_size = max(1, len(data) // num_blocks)
    result = []
    for i in range(0, len(data), block_size):
        chunk = data[i:i + block_size]
        if chunk:
            result.append(shannon_entropy(chunk))
        if len(result) >= num_blocks:
            break
    return result


def entropy_assessment(data: bytes, mime_type: str | None = None) -> dict:
    entropy = shannon_entropy(data)
    size = len(data)
    severity = "INFO"
    summary = f"Entropy: {entropy:.2f}"
    if size >= 256 and entropy >= 7.6:
        severity = "MEDIUM"
        summary = f"High entropy: {entropy:.2f}"
    elif size >= 128 and entropy >= 7.2:
        severity = "LOW"
        summary = f"Elevated entropy: {entropy:.2f}"
    return {
        "entropy": entropy,
        "size": size,
        "mime_type": mime_type or "",
        "severity": severity,
        "summary": summary,
    }


def fuzzy_hashes(data: bytes) -> dict:
    results = {}
    if not data:
        return results

    if ssdeep is not None:
        try:
            results["ssdeep"] = ssdeep.hash(data)
        except Exception as exc:
            log.debug("ssdeep hash failed: %s", exc)

    if tlsh is not None and len(data) >= 50:
        try:
            value = tlsh.hash(data)
            if value and value != "TNULL":
                results["tlsh"] = value
        except Exception as exc:
            log.debug("TLSH hash failed: %s", exc)

    return results


def _builtin_yara_dir() -> Path:
    """Return the builtin YARA rules directory shipped with MATT."""
    return Path(__file__).parent.parent / "yara" / "builtin"


def _default_user_yara_dir() -> Path:
    """Return the per-user default YARA folder (~/.matt/yara/)."""
    return Path.home() / ".matt" / "yara"


def _collect_yara_dirs() -> list[Path]:
    """Return the ordered list of YARA rule directories to load.

    Priority (all are loaded and compiled together):
      1. yara/builtin/         — rules shipped with MATT (always included)
      2. ~/.matt/yara/         — per-user default folder (same root as future caches)
      3. flags.yara_rules_dir  — CLI-supplied path (community rulesets / custom)
    """
    dirs = [_builtin_yara_dir(), _default_user_yara_dir()]
    cli_dir = getattr(flags, "yara_rules_dir", None)
    if cli_dir:
        dirs.append(Path(cli_dir))
    return dirs


def _rules_signature(dirs: list[Path]) -> tuple | None:
    entries = []
    for base in dirs:
        if not base.is_dir():
            continue
        for rule_path in sorted(base.rglob("*")):
            if not rule_path.is_file():
                continue
            if rule_path.suffix.lower() not in {".yar", ".yara"}:
                continue
            stat = rule_path.stat()
            entries.append((str(rule_path), stat.st_mtime_ns, stat.st_size))
    if not entries:
        return None
    return tuple(entries)


@functools.lru_cache(maxsize=8)
def _compile_yara_rules(signature: tuple):
    if yara is None or not signature:
        return None
    filepaths = {str(index): rule_path for index, (rule_path, _mtime, _size) in enumerate(signature)}
    return yara.compile(filepaths=filepaths)


def scan_yara(data: bytes) -> list[dict]:
    if yara is None:
        return []

    dirs = _collect_yara_dirs()
    signature = _rules_signature(dirs)
    if not signature:
        return []

    try:
        rules = _compile_yara_rules(signature)
        if rules is None:
            return []
        matches = rules.match(data=data)
    except Exception as exc:
        log.debug("YARA scan failed: %s", exc)
        return []

    results = []
    for match in matches:
        results.append(
            {
                "rule": getattr(match, "rule", ""),
                "namespace": getattr(match, "namespace", ""),
                "tags": list(getattr(match, "tags", [])),
                "meta": dict(getattr(match, "meta", {})),
            }
        )
    return results


@functools.lru_cache(maxsize=256)
def _lookup_virustotal_cached(sha256: str, api_key: str):
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    req = urlrequest.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    with urlrequest.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "sha256": sha256,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "timeout": int(stats.get("timeout", 0)),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "reputation": attrs.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/file/{sha256}",
    }


def _vt_api_key() -> str | None:
    return getattr(flags, "vt_api_key", None) or os.getenv("VT_API_KEY") or os.getenv("VIRUSTOTAL_API_KEY")


def _vt_is_online() -> bool:
    return getattr(flags, "network_policy", "passive") == "online"


def lookup_virustotal(sha256: str) -> dict | None:
    if not _vt_is_online():
        return None
    api_key = _vt_api_key()
    if not api_key:
        return None
    try:
        return _lookup_virustotal_cached(sha256, api_key)
    except urlerror.URLError as exc:
        log.debug("VirusTotal lookup failed: %s", exc)
    except Exception as exc:
        log.debug("VirusTotal lookup failed: %s", exc)
    return None


# ------------------------------------------------------------------
# VT IOC enrichment: domain and IP lookups
# ------------------------------------------------------------------

@functools.lru_cache(maxsize=256)
def _lookup_vt_domain_cached(domain: str, api_key: str):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    req = urlrequest.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    with urlrequest.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "domain": domain,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "reputation": attrs.get("reputation"),
        "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
    }


def lookup_virustotal_domain(domain: str) -> dict | None:
    if not _vt_is_online():
        return None
    api_key = _vt_api_key()
    if not api_key:
        return None
    try:
        return _lookup_vt_domain_cached(domain, api_key)
    except (urlerror.URLError, Exception) as exc:
        log.debug("VT domain lookup failed for %s: %s", domain, exc)
    return None


@functools.lru_cache(maxsize=256)
def _lookup_vt_ip_cached(ip: str, api_key: str):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    req = urlrequest.Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    with urlrequest.urlopen(req, timeout=10) as resp:
        payload = json.loads(resp.read().decode("utf-8", errors="replace"))
    attrs = payload.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "ip": ip,
        "malicious": int(stats.get("malicious", 0)),
        "suspicious": int(stats.get("suspicious", 0)),
        "harmless": int(stats.get("harmless", 0)),
        "undetected": int(stats.get("undetected", 0)),
        "reputation": attrs.get("reputation"),
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


def lookup_virustotal_ip(ip: str) -> dict | None:
    if not _vt_is_online():
        return None
    api_key = _vt_api_key()
    if not api_key:
        return None
    try:
        return _lookup_vt_ip_cached(ip, api_key)
    except (urlerror.URLError, Exception) as exc:
        log.debug("VT IP lookup failed for %s: %s", ip, exc)
    return None


_MAX_ENRICHMENT_LOOKUPS = 10


def enrich_iocs(ioc_data: dict) -> dict:
    if not _vt_is_online() or not _vt_api_key():
        return {}
    results = {}
    budget = _MAX_ENRICHMENT_LOOKUPS
    for domain in (ioc_data.get("domains") or []):
        if budget <= 0:
            break
        vt = lookup_virustotal_domain(domain)
        if vt:
            results[domain] = vt
            budget -= 1
    for ip in (ioc_data.get("ipv4") or []) + (ioc_data.get("ipv6") or []):
        if budget <= 0:
            break
        vt = lookup_virustotal_ip(ip)
        if vt:
            results[ip] = vt
            budget -= 1
    return results


def mitre_attack_techniques(struct, analyzer) -> list[dict]:
    reports = list(analyzer.reports.values())
    labels = {report.label for report in reports}
    filename = (getattr(struct, "filename", "") or "").lower()
    analyzer_name = type(analyzer).__name__
    script_type = str(analyzer.reports.get("script_type", "") or "").lower()
    behavior_text = " ".join(str(report.text or "") for report in reports).lower()

    techniques = []

    def add(technique_id: str, name: str, reason: str):
        for existing in techniques:
            if existing["id"] == technique_id:
                return
        techniques.append({"id": technique_id, "name": name, "reason": reason})

    if "remote_template" in labels:
        add("T1221", "Template Injection", "Remote Office template relationship")

    if labels & {"macros_found", "vba_macros", "has_vba", "vba_analysis"} or analyzer_name == "VBAProjectAnalyzer":
        add("T1204.002", "User Execution: Malicious File", "VBA macro-enabled document")

    if "encryption" in labels:
        add("T1027.013", "Obfuscated Files or Information: Encrypted Archive", "Encrypted container or archive")

    if analyzer_name == "ScriptAnalyzer":
        if filename.endswith((".js", ".jse", ".hta")) or "javascript" in script_type or "html application" in script_type:
            add("T1059.007", "Command and Scripting Interpreter: JavaScript", "JavaScript or HTA payload")
        if filename.endswith((".ps1", ".psm1")) or "powershell" in script_type or "powershell invocation" in behavior_text:
            add("T1059.001", "Command and Scripting Interpreter: PowerShell", "PowerShell payload or invocation")
        if filename.endswith((".vbs", ".vbe", ".wsf", ".wsh")) or "vbscript" in script_type:
            add("T1059.005", "Command and Scripting Interpreter: Visual Basic", "VBScript or WSH payload")
        if filename.endswith((".bat", ".cmd")) or "cmd.exe invocation" in behavior_text:
            add("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Batch or command shell payload")

    # General behavior-based techniques (not gated to a specific analyzer)
    if "download cradle" in behavior_text or "ingress tool transfer" in behavior_text:
        add("T1105", "Ingress Tool Transfer", "Download cradle detected")
    if "obfuscation score" in behavior_text and ("high" in behavior_text or "critical" in behavior_text):
        add("T1027", "Obfuscated Files or Information", "Heavy obfuscation detected")
    if "registry" in behavior_text and "run" in behavior_text:
        add("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Registry persistence")
    if "scheduled task" in behavior_text or "schtasks" in behavior_text:
        add("T1053", "Scheduled Task/Job", "Task scheduler persistence")
    if "mshta" in behavior_text:
        add("T1218.005", "System Binary Proxy Execution: Mshta", "Mshta execution")
    if "rundll32" in behavior_text:
        add("T1218.011", "System Binary Proxy Execution: Rundll32", "Rundll32 execution")

    return techniques


def _parse_timestamp(value) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text or parse_date is None:
        return None
    try:
        parsed = parse_date(text)
    except (ValueError, TypeError):
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def collect_timeline_events(root) -> list[dict]:
    events = []

    def add_event(timestamp, source, event, details=None):
        dt = _parse_timestamp(timestamp)
        if not dt:
            return
        events.append(
            {
                "timestamp": dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                "source": source,
                "event": event,
                "details": details or "",
            }
        )

    def walk(struct):
        source = getattr(struct, "filename", None) or getattr(struct, "mime_type", "object")
        for report in struct.analyzer.summary:
            if report.label == "date":
                ts = report.data["timestamp"] if isinstance(report.data, dict) and report.data.get("timestamp") else report.text
                add_event(ts, source, "Email date", str(report.text))
            elif report.label == "route" and isinstance(report.data, list):
                for hop in report.data:
                    if hop.get("timestamp"):
                        details = f"{hop.get('from')} -> {hop.get('by')}"
                        add_event(hop["timestamp"], source, "Mail relay hop", details)
            elif report.label == "archive" and isinstance(report.data, dict) and report.data.get("archive_modified"):
                member = report.data.get("archive_filename") or source
                add_event(report.data["archive_modified"], member, "Archive member timestamp", report.data.get("archive_type", "archive"))
            elif report.label == "compile_time" and isinstance(report.data, dict) and report.data.get("timestamp") is not None:
                add_event(report.data["timestamp"], source, "PE compile time", str(report.text))
        for child in struct.get_children():
            walk(child)

    walk(root)
    events.sort(key=lambda item: item["timestamp"])
    return events
