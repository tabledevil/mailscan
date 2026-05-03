"""Audit follow-up — Structure cache must include filename/mime in key.

Audit finding (codex_security_1, codex_security_2; HIGH severity):
``Structure.create()`` cached on SHA-256 only, so identical bytes
seen first as ``readme.txt`` would mask later occurrences as
``payload.js`` — every filename-based detection (dangerous_extension,
ScriptAnalyzer.can_handle, VBAProjectAnalyzer.can_handle) silently
returned the cached Structure with the benign filename.

These tests pin the corrected cache-key shape so future cleanup
can't silently restore the order-dependent false-negative path.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


# ---------------------------------------------------------------
# The bug — same bytes, benign filename first, dangerous filename second
# ---------------------------------------------------------------


def test_same_bytes_different_filename_yields_distinct_structures():
    """The exact attack shape codex flagged: a benign-named file and a
    dangerous-named file with identical bytes must NOT share a Structure."""
    data = b"alert('hello');\n"
    s_benign = Structure.create(data=data, filename="readme.txt",
                                mime_type="text/plain")
    s_dangerous = Structure.create(data=data, filename="payload.js",
                                   mime_type="text/plain")
    assert s_benign is not s_dangerous
    assert s_benign.filename == "readme.txt"
    assert s_dangerous.filename == "payload.js"


def test_dangerous_extension_fires_when_seen_after_benign():
    """The actual analyst-visible consequence: dangerous_extension report
    must still fire on payload.js even when readme.txt was seen first."""
    data = b"alert('hello');\n"
    s_benign = Structure.create(data=data, filename="readme.txt",
                                mime_type="text/plain")
    assert "dangerous_extension" not in s_benign.analyzer.reports

    s_dangerous = Structure.create(data=data, filename="payload.js",
                                   mime_type="text/plain")
    assert "dangerous_extension" in s_dangerous.analyzer.reports


# ---------------------------------------------------------------
# Dedup of true duplicates still works
# ---------------------------------------------------------------


def test_identical_filename_and_bytes_still_dedups():
    """When the same file is created twice with the same name + mime, the
    cache hit is correct — analyzing twice would be wasteful and would
    double-count IOCs."""
    data = b"hello world\n"
    s1 = Structure.create(data=data, filename="note.txt",
                          mime_type="text/plain")
    s2 = Structure.create(data=data, filename="note.txt",
                          mime_type="text/plain")
    assert s1 is s2


def test_no_filename_dedups_purely_on_content():
    """Inline body parts arrive with filename=None; identical payloads
    should still collapse to one Structure."""
    data = b"hello\n"
    s1 = Structure.create(data=data, mime_type="text/plain")
    s2 = Structure.create(data=data, mime_type="text/plain")
    assert s1 is s2


def test_basename_normalization_dedups_across_paths():
    """Two attachments with the same basename but different paths are
    the same artifact for analysis purposes — dedup."""
    data = b"identical\n"
    s1 = Structure.create(data=data, filename="dir1/file.txt",
                          mime_type="text/plain")
    s2 = Structure.create(data=data, filename="other/dir2/file.txt",
                          mime_type="text/plain")
    assert s1 is s2


# ---------------------------------------------------------------
# Mime-type discrimination (rare but real)
# ---------------------------------------------------------------


def test_same_bytes_different_mime_yields_distinct_structures():
    """The same byte sequence can arrive labelled as text/plain in one
    context and application/javascript in another (e.g. a multipart
    body where the sender mislabels). Different MIME → different
    analysis dispatch → must not share Structure."""
    data = b"function x() { return 1; }\n"
    s_text = Structure.create(data=data, filename="x", mime_type="text/plain")
    s_js = Structure.create(data=data, filename="x",
                            mime_type="application/javascript")
    assert s_text is not s_js
