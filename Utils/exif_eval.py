"""Evaluate exiftool output instead of only appending it.

``evaluate(grouped, ...)`` takes the grouped exiftool dict that
``Analyzer._report_exiftool`` builds (``{"FlashPix": {"Author": ...}, ...}``)
and returns normalized document/media metadata plus typed findings:

* fields — author, last modified by, company, creating software, created /
  modified / printed timestamps, revision, edit time, template, page/word
  counts, camera, GPS position, embedded thumbnail, exiftool's file type
* findings — extension vs. content mismatch, remote template, GPS position,
  timestamp anomalies, URLs/UNC paths in metadata

Pure functions, no exiftool call here — easy to test with canned dicts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional

# Field name → normalized key; first non-empty wins (groups searched in order).
_FIELD_MAP = {
    "author": ("Author", "Creator", "Artist", "By-line"),
    "last_modified_by": ("LastModifiedBy",),
    "company": ("Company", "Manager"),
    "software": ("Software", "Application", "AppVersion", "CreatorTool", "Producer",
                 "CreatorApp", "HistorySoftwareAgent"),
    "producer": ("Producer",),
    "title": ("Title",),
    "created": ("CreateDate", "DateTimeOriginal", "CreationDate", "MetadataDate"),
    "modified": ("ModifyDate", "ModDate"),
    "printed": ("LastPrinted",),
    "revision": ("RevisionNumber", "Revision"),
    "edit_time": ("TotalEditTime", "TotalTime"),
    "template": ("Template", "AttachedTemplate"),
    "pages": ("Pages", "PageCount", "Slides"),
    "words": ("Words",),
    "camera_make": ("Make",),
    "camera_model": ("Model",),
    "gps": ("GPSPosition",),
    "gps_lat": ("GPSLatitude",),
    "gps_lon": ("GPSLongitude",),
    "file_type": ("FileType",),
    "file_type_ext": ("FileTypeExtension",),
    "exif_mime": ("MIMEType",),
}
_GROUP_ORDER = ("FlashPix", "XML", "PDF", "XMP", "EXIF", "IPTC", "Composite",
                "QuickTime", "File", "ZIP", "RTF", "HTML")
_THUMB_FIELDS = ("ThumbnailImage", "PreviewImage", "ThumbnailTIFF", "JpgFromRaw")
_URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>]+|\\\\[A-Za-z0-9._-]+\\[^\s\"'<>]+", re.I)
_DATE_RE = re.compile(r"^(\d{4}):(\d{2}):(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?")

# Extensions that denote the same content type (exiftool's canonical ext first).
_EXT_ALIASES = [
    {"jpg", "jpeg", "jpe", "jfif"}, {"tif", "tiff"}, {"htm", "html", "xhtml"},
    {"mht", "mhtml"}, {"txt", "text", "log", "csv", "md", "ini", "cfg"},
    {"xml", "xsd", "xsl", "svg", "rels"},
    {"doc", "dot"}, {"xls", "xlt"}, {"ppt", "pot", "pps"}, {"mpg", "mpeg"},
    {"zip", "jar", "apk", "xpi", "nupkg"}, {"gz", "tgz"}, {"mp4", "m4v", "m4a"},
]
# exiftool types too generic to contradict a filename.
_WEAK_TYPES = {"txt", "xml", "html", "zip", "fpx", "", "tar", "json"}
_RISKY_EXTS = {"exe", "dll", "scr", "com", "msi", "js", "jse", "vbs", "vbe", "hta",
               "ps1", "bat", "cmd", "wsf", "lnk", "jar", "docm", "xlsm", "pptm",
               "dotm", "xlam", "ppam", "rtf", "chm", "iso", "img", "one"}


@dataclass
class ExifFinding:
    code: str
    severity: str          # Severity enum name
    text: str
    data: dict = field(default_factory=dict)


def _first(grouped: Dict[str, Dict[str, str]], names) -> Optional[str]:
    groups = [g for g in _GROUP_ORDER if g in grouped] + \
             [g for g in grouped if g not in _GROUP_ORDER]
    for name in names:
        for g in groups:
            v = grouped[g].get(name)
            if v not in (None, ""):
                return str(v)
    return None


def parse_exif_date(value: Optional[str]) -> Optional[datetime]:
    """exiftool ``YYYY:MM:DD HH:MM:SS[.f][Z|±HH:MM]`` → aware datetime (UTC
    assumed when no zone).  Zero dates (``0000:00:00``) → None."""
    if not value:
        return None
    m = _DATE_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s))
    except ValueError:
        return None
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        hh, mm = int(tz[1:3]), int(tz[-2:])
        return dt.replace(tzinfo=timezone(sign * timedelta(hours=hh, minutes=mm)))
    return dt.replace(tzinfo=timezone.utc)


def _same_ext(a: str, b: str) -> bool:
    if a == b:
        return True
    return any(a in s and b in s for s in _EXT_ALIASES)


def evaluate(grouped: Dict[str, Dict[str, str]], *, filename: Optional[str] = None,
             has_real_filename: bool = False,
             now: Optional[datetime] = None) -> tuple:
    """Return ``(fields, findings)``; ``fields`` holds only what was present."""
    now = now or datetime.now(timezone.utc)
    fields: Dict[str, object] = {}
    for key, names in _FIELD_MAP.items():
        v = _first(grouped, names)
        if v is not None:
            fields[key] = v
    if any(f in g for g in grouped.values() for f in _THUMB_FIELDS):
        fields["thumbnail"] = True
    findings: List[ExifFinding] = []

    # -- timestamps -------------------------------------------------------
    stamps = {k: parse_exif_date(fields.get(k)) for k in ("created", "modified", "printed")}
    stamps = {k: v for k, v in stamps.items() if v is not None}
    if stamps:
        fields["timestamps"] = {k: v.isoformat() for k, v in stamps.items()}
    c, m = stamps.get("created"), stamps.get("modified")
    if c and m and m < c - timedelta(minutes=1):
        findings.append(ExifFinding("META_MODIFIED_BEFORE_CREATED", "LOW",
                                    f"Modified ({m.isoformat()}) before created ({c.isoformat()})",
                                    {"created": c.isoformat(), "modified": m.isoformat()}))
    future = {k: v.isoformat() for k, v in stamps.items() if v > now + timedelta(days=1)}
    if future:
        findings.append(ExifFinding("META_FUTURE_TIMESTAMP", "LOW",
                                    "Timestamp in the future: " + ", ".join(
                                        f"{k} {v}" for k, v in future.items()), future))

    # -- template / URLs --------------------------------------------------
    urls: List[str] = []
    for g, fs in grouped.items():
        if g == "File":
            continue
        for k, v in fs.items():
            for u in _URL_RE.findall(str(v)):
                urls.append(u)
                if "template" in k.lower():
                    findings.append(ExifFinding(
                        "META_REMOTE_TEMPLATE", "HIGH",
                        f"Document template points to a remote location: {u} "
                        "(template injection)", {"field": f"{g}:{k}", "url": u}))
    if urls:
        fields["urls"] = sorted(set(urls))
        if not any(f.code == "META_REMOTE_TEMPLATE" for f in findings):
            findings.append(ExifFinding("META_URLS", "INFO",
                                        "URLs/UNC paths in metadata: " + ", ".join(sorted(set(urls))),
                                        {"urls": sorted(set(urls))}))

    # -- GPS ----------------------------------------------------------------
    if "gps" in fields or ("gps_lat" in fields and "gps_lon" in fields):
        pos = fields.get("gps") or f"{fields['gps_lat']}, {fields['gps_lon']}"
        findings.append(ExifFinding("META_GPS", "LOW", f"GPS position in metadata: {pos}",
                                    {"position": pos}))

    # -- extension vs. content ------------------------------------------------
    actual = (fields.get("file_type_ext") or "").lower()
    if has_real_filename and filename and "." in filename and actual not in _WEAK_TYPES:
        ext = filename.rsplit(".", 1)[-1].lower()
        if ext and len(ext) <= 5 and not _same_ext(ext, actual):
            sev = "MEDIUM" if actual in _RISKY_EXTS else "LOW"
            findings.append(ExifFinding(
                "META_EXTENSION_MISMATCH", sev,
                f"File name says .{ext}, content is {fields.get('file_type', actual)} (.{actual})",
                {"extension": ext, "content": actual}))
    return fields, findings


def summary_line(fields: Dict[str, object]) -> str:
    """Short one-liner: ``Author · Software · created 2021-03-02``."""
    parts = []
    who = fields.get("author") or fields.get("last_modified_by")
    if who:
        parts.append(str(who))
    if fields.get("company"):
        parts.append(str(fields["company"]))
    if fields.get("software"):
        parts.append(str(fields["software"]))
    cam = " ".join(str(fields[k]) for k in ("camera_make", "camera_model") if fields.get(k))
    if cam:
        parts.append(cam)
    ts = fields.get("timestamps") or {}
    if ts.get("created"):
        parts.append("created " + ts["created"][:10])
    if ts.get("modified") and ts.get("modified", "")[:10] != ts.get("created", "")[:10]:
        parts.append("modified " + ts["modified"][:10])
    if fields.get("gps") or fields.get("gps_lat"):
        parts.append("GPS")
    return " · ".join(parts)
