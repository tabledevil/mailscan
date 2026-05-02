"""E2E findings — failing tests for items in docs/TODO_E2E.md.

Each test pins down a concrete behavior the tool currently lacks.
Tests start out red and turn green as fixes land.
"""

import io
import logging
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity, Report
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear_caches():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# ---------------------------------------------------------------
# #2 ScriptAnalyzer.can_handle gate
# ---------------------------------------------------------------

OBFUSCATED_THIS_ASSIGN_JS = (
    '    this.XRJCFXTXIVSNEQJSQNFXTKWWIAJGNTSDW += "AAAAAAAA";\n' * 200
).encode("utf-8")


def test_script_analyzer_handles_obfuscated_this_assignment_js():
    """Real BEC droppers are wall-of-`this.X += "..."` with no var/let/function
    in the first 4 KB. Filename ends in .JS and MIME is text/plain. The
    analyzer must still claim the file."""
    from Analyzers.ScriptAnalyzer import ScriptAnalyzer

    s = Structure.create(
        data=OBFUSCATED_THIS_ASSIGN_JS,
        filename="SWIFT900928817829EURO.JS",
        mime_type="text/plain",
    )
    assert ScriptAnalyzer.can_handle(s) is True


def test_script_analyzer_handles_jscript_encoded_marker():
    """JScript.Encoded files start with `#@~^` — must be recognized regardless
    of content-keyword scan."""
    from Analyzers.ScriptAnalyzer import ScriptAnalyzer

    data = b"#@~^AAAAAA==BBBBB" + b"X" * 1024
    s = Structure.create(data=data, filename="payload.jse", mime_type="text/plain")
    assert ScriptAnalyzer.can_handle(s) is True


def test_script_analyzer_extension_alone_sufficient_for_short_js():
    """A `.js` filename without keyword hits should still be picked up if the
    content is plausibly script-like (printable, low entropy)."""
    from Analyzers.ScriptAnalyzer import ScriptAnalyzer

    data = b'a["b"]="c";' * 100
    s = Structure.create(data=data, filename="loader.js", mime_type="text/plain")
    assert ScriptAnalyzer.can_handle(s) is True


# ---------------------------------------------------------------
# #3 Report.label autofill from dict key
# ---------------------------------------------------------------


def test_report_label_autofills_from_dict_key():
    """Reports added as `self.reports['summary'] = Report(text)` without an
    explicit `label=` kwarg should expose `label == 'summary'` after analysis,
    so renderers don't emit empty <span class="report-label"></span>."""
    from Analyzers.PlainTextAnalyzer import PlainTextAnalyzer  # noqa: F401

    s = Structure.create(
        data=b"hello world\n",
        filename="hello.txt",
        mime_type="text/plain",
    )
    reports = s.analyzer.reports
    # 'summary' and 'language' are emitted by PlainTextAnalyzer without label=
    assert "summary" in reports
    assert reports["summary"].label == "summary"
    assert "language" in reports
    assert reports["language"].label == "language"


def test_no_empty_labels_in_default_emails():
    """No report on a benign plain text file should have an empty label."""
    s = Structure.create(
        data=b"Hello, world. info@example.com\n",
        filename="note.txt",
        mime_type="text/plain",
    )
    empty = [k for k, r in s.analyzer.reports.items() if not r.label]
    assert empty == [], f"reports with empty labels: {empty}"


# ---------------------------------------------------------------
# #4 ZipAnalyzer logging hygiene
# ---------------------------------------------------------------


def _make_aes_encrypted_zip_bytes() -> bytes:
    """Return raw bytes of a ZIP that uses an AES/unsupported compression so
    pyzipper raises 'compression method not supported' during password test.

    Approximation: build a normal encrypted ZIP via stdlib (ZipCrypto) and
    flip the version-needed-to-extract; if pyzipper still handles it, we
    fall back to skipping. The point of the test is the *logger routing*."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.txt", b"hello")
    return bio.getvalue()


def test_zip_analyzer_does_not_log_to_root_logger(caplog):
    """logging.error/warning calls in ZipAnalyzer must go through the `matt`
    logger, never the root logger."""
    s = Structure.create(
        data=_make_aes_encrypted_zip_bytes(),
        filename="t.zip",
        mime_type="application/zip",
    )
    # Drive a code path that historically used logging.* directly: feed in
    # a malformed zip to trigger BadZipFile-style errors.
    bad = b"PK\x03\x04" + b"\x00" * 30
    with caplog.at_level(logging.DEBUG, logger=""):
        Structure.create(data=bad, filename="bad.zip", mime_type="application/zip")
    root_records = [r for r in caplog.records if r.name == "root"]
    assert root_records == [], f"root logger used: {[r.message for r in root_records]}"
    _ = s  # keep s referenced


# ---------------------------------------------------------------
# #5 Aggregate IOC report at root
# ---------------------------------------------------------------


def test_root_has_aggregate_ioc_report():
    """After a multi-child analysis, the root Structure should expose an
    aggregate `iocs_aggregate` (or similarly-named) report listing the union
    of IOCs found across descendants."""
    body = (
        b"From: a@example.com\r\n"
        b"To: b@example.org\r\n"
        b"Subject: t\r\n"
        b"\r\n"
        b"Visit http://malicious.example.com/path and call 8.8.8.8\r\n"
    )
    s = Structure.create(data=body, filename="t.eml", mime_type="message/rfc822")

    root_reports = s.analyzer.reports
    agg_keys = [k for k in root_reports if "ioc" in k.lower() and "agg" in k.lower()]
    assert agg_keys, f"no aggregate IOC report on root; keys={list(root_reports)}"

    text = root_reports[agg_keys[0]].text
    # Some form of the URL/IP/email must appear (defang allowed)
    assert "malicious" in text.lower()
    assert "8.8.8.8" in text or "8[.]8[.]8[.]8" in text


# ---------------------------------------------------------------
# #6 Extraction preserves original filename extension
# ---------------------------------------------------------------


def test_extraction_preserves_original_extension(tmp_path):
    """A file whose original name ends in `.JS` but whose detected MIME is
    `text/plain` must extract as `.js` (or `.JS`), not `.txt`."""
    s = Structure.create(
        data=OBFUSCATED_THIS_ASSIGN_JS,
        filename="SWIFT900928817829EURO.JS",
        mime_type="text/plain",
    )
    s.extract(basepath=str(tmp_path))
    written = list(tmp_path.iterdir())
    exts = {p.suffix.lower() for p in written if p.is_file()}
    assert ".js" in exts, f"extracted files: {[p.name for p in written]}"


# ---------------------------------------------------------------
# #21 sample corpus housekeeping
# ---------------------------------------------------------------


def test_email_analyzer_does_not_recurse_on_quoted_forward():
    """Forwarded/quoted email bodies contain `From:`/`Subject:` lines that
    used to satisfy EmailAnalyzer.can_handle on text/plain children, causing
    runaway recursion to max_analysis_depth. Regression guard."""
    quoted = (
        b"From: outer@a.example\r\nTo: outer@b.example\r\nSubject: fwd\r\n\r\n"
        b"On Mon, Jan 1 2026, Alice wrote:\r\n"
        b"> From: alice@example.com\r\n"
        b"> Subject: original\r\n"
        b"> Date: Mon, 1 Jan 2026 00:00:00 +0000\r\n"
        b"> Message-ID: <orig@x.example>\r\n"
        b"> To: bob@example.com\r\n"
        b"> \r\n"
        b"> hello\r\n"
    )
    s = Structure.create(data=quoted, filename="t.eml", mime_type="message/rfc822")

    def max_depth(node, depth=0):
        m = depth
        for c in node.get_children():
            m = max(m, max_depth(c, depth + 1))
        return m

    assert max_depth(s) <= 4, f"unexpected depth {max_depth(s)} — recursive can_handle?"


def test_testfiles_zip_corpus_consistency():
    """All ZIPs in testfiles/ should be encrypted (the corpus exists to
    exercise the encrypted-archive path). If a ZIP slipped in unencrypted,
    either remove it or move it elsewhere."""
    import pathlib

    repo = pathlib.Path(__file__).resolve().parents[1]
    zips = sorted((repo / "testfiles").glob("*.zip"))
    offenders = []
    for z in zips:
        with zipfile.ZipFile(z, "r") as zf:
            if not all(i.flag_bits & 0x1 for i in zf.infolist()):
                offenders.append(z.name)
    assert offenders == [], f"unencrypted entries in: {offenders}"
