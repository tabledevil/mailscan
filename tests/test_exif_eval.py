"""exiftool output is evaluated into metadata fields and findings."""

import os
import shutil
import sys
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Utils import exif_eval
from Utils.exif_eval import evaluate, parse_exif_date, summary_line

NOW = datetime(2026, 11, 23, tzinfo=timezone.utc)


def _codes(findings):
    return {f.code: f for f in findings}


def test_office_fields_and_summary():
    g = {"FlashPix": {"Author": "J. Doe", "LastModifiedBy": "Admin", "Company": "ACME",
                      "Software": "Microsoft Office Word", "CreateDate": "2021:03:02 10:11:00",
                      "ModifyDate": "2021:03:04 08:00:00", "RevisionNumber": "7",
                      "Template": "Normal.dotm"},
         "File": {"FileType": "DOC", "FileTypeExtension": "doc"}}
    fields, findings = evaluate(g, filename="a.doc", has_real_filename=True, now=NOW)
    assert fields["author"] == "J. Doe" and fields["company"] == "ACME"
    assert fields["timestamps"]["created"].startswith("2021-03-02T10:11:00")
    assert findings == []
    assert summary_line(fields) == ("J. Doe · ACME · Microsoft Office Word · "
                                    "created 2021-03-02 · modified 2021-03-04")


def test_remote_template_is_high_and_url_kept():
    g = {"FlashPix": {"Template": "https://evil.example/t.dotm"}}
    fields, findings = evaluate(g, now=NOW)
    f = _codes(findings)["META_REMOTE_TEMPLATE"]
    assert f.severity == "HIGH" and f.data["url"] == "https://evil.example/t.dotm"
    assert fields["urls"] == ["https://evil.example/t.dotm"]


def test_unc_path_in_metadata():
    g = {"XML": {"HyperlinkBase": "\\\\files.example\\share\\x"}}
    _fields, findings = evaluate(g, now=NOW)
    assert "META_URLS" in _codes(findings)


def test_timestamp_anomalies():
    g = {"PDF": {"CreateDate": "2022:05:01 12:00:00+02:00",
                 "ModifyDate": "2020:01:01 00:00:00Z"}}
    assert "META_MODIFIED_BEFORE_CREATED" in _codes(evaluate(g, now=NOW)[1])
    g = {"PDF": {"CreateDate": "2031:01:01 00:00:00"}}
    assert "META_FUTURE_TIMESTAMP" in _codes(evaluate(g, now=NOW)[1])


def test_zero_and_garbage_dates_ignored():
    assert parse_exif_date("0000:00:00 00:00:00") is None
    assert parse_exif_date("yesterday") is None
    assert parse_exif_date("2021:03:02 10:11:12.55+01:00").utcoffset().total_seconds() == 3600


def test_gps_position():
    g = {"Composite": {"GPSPosition": "52 deg 31' 12.00\" N, 13 deg 24' 18.00\" E"},
         "EXIF": {"Make": "Canon", "Model": "EOS"}}
    fields, findings = evaluate(g, now=NOW)
    assert _codes(findings)["META_GPS"].severity == "LOW"
    assert "Canon EOS" in summary_line(fields) and "GPS" in summary_line(fields)


@pytest.mark.parametrize("name,ext,sev", [
    ("invoice.pdf", "exe", "MEDIUM"),
    ("report.doc", "rtf", "MEDIUM"),
    ("photo.png", "jpg", "LOW"),
])
def test_extension_mismatch(name, ext, sev):
    g = {"File": {"FileType": ext.upper(), "FileTypeExtension": ext}}
    f = _codes(evaluate(g, filename=name, has_real_filename=True, now=NOW)[1])
    assert f["META_EXTENSION_MISMATCH"].severity == sev


@pytest.mark.parametrize("name,ext", [
    ("photo.jpeg", "jpg"), ("page.htm", "html"), ("notes.txt", "txt"),
    ("mail.eml", "txt"), ("data.xml", "xml"),
])
def test_extension_aliases_and_weak_types_not_flagged(name, ext):
    g = {"File": {"FileType": ext.upper(), "FileTypeExtension": ext}}
    codes = _codes(evaluate(g, filename=name, has_real_filename=True, now=NOW)[1])
    assert "META_EXTENSION_MISMATCH" not in codes


def test_synthetic_names_not_compared():
    g = {"File": {"FileType": "EXE", "FileTypeExtension": "exe"}}
    codes = _codes(evaluate(g, filename="abcd1234.bin", has_real_filename=False, now=NOW)[1])
    assert "META_EXTENSION_MISMATCH" not in codes


@pytest.mark.skipif(not shutil.which("exiftool"), reason="exiftool not installed")
def test_exiftool_integration_rtf_named_doc():
    from structure import Structure
    from Utils.password_broker import PasswordBroker
    Structure.clear_cache()
    PasswordBroker.clear()
    s = Structure.create(data=b"{\\rtf1\\ansi{\\info{\\author Mallory}}Hello}", filename="x.doc")
    reps = s.analyzer.reports
    assert reps["metadata"].data.get("author") == "Mallory"
    assert reps["meta_extension_mismatch"].data["content"] == "rtf"
    Structure.clear_cache()


def test_text_and_mail_skip_exiftool(monkeypatch):
    from structure import Structure
    calls = []
    monkeypatch.setattr("subprocess.run", lambda *a, **k: calls.append(a) or (_ for _ in ()).throw(RuntimeError()))
    Structure.clear_cache()
    Structure.create(data=b"just text\n", filename="a.txt", mime_type="text/plain")
    Structure.create(data=b"From: a@x.example\r\n\r\nb\n", filename="m.eml",
                     mime_type="message/rfc822")
    assert not [c for c in calls if c and c[0] and c[0][0] == "exiftool"]
    Structure.clear_cache()
