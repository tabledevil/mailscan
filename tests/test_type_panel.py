"""Sprint 7 — B4: exiftool excluded from the MIME provider type panel."""

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


def test_rich_type_panel_does_not_include_exiftool_row():
    """exiftool routinely mis-classifies email as text/plain. It used to appear
    as a peer of python_magic/file_command/magika in the type panel, which
    suggested provider disagreement. Confirm the renderer no longer adds it."""
    eml = b"From: a@x.example\r\nTo: b@x.example\r\nSubject: t\r\n\r\nbody\n"
    s = Structure.create(data=eml, filename="t.eml", mime_type="message/rfc822")
    out = s.get_report(report_format="rich", verbosity=0)

    # The panel labels each provider; exiftool shouldn't show up there.
    # Strip ANSI escape sequences for a robust assertion.
    import re
    plain = re.sub(r"\x1b\[[0-9;]*m", "", out)

    # `type` block contains provider rows. exiftool can still appear in the
    # exiftool *metadata* report panel, but not as a `provider | mime | desc`
    # row in the type detection panel.
    type_block_start = plain.find("type")
    type_block_end = plain.find("md5", type_block_start)
    type_block = plain[type_block_start:type_block_end] if type_block_start >= 0 else plain
    assert "exiftool" not in type_block, type_block
