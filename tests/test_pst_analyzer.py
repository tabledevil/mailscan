"""PstAnalyzer — native PST/OST analysis via pstforensic, inside MATT."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Severity, Structure
from Utils.password_broker import PasswordBroker
from pstforensic.tests import synth


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _analyze(img, name="mailbox.pst"):
    return Structure.create(data=img, filename=name)


def test_registered_and_primary_for_pst():
    from Analyzers import PstAnalyzer
    s = _analyze(synth.build_unicode_pst_tree())
    assert isinstance(s.analyzer, PstAnalyzer)


def test_msg_analyzer_declines_pst():
    from Analyzers import MsgAnalyzer
    s = _analyze(synth.build_unicode_pst_tree())
    assert not MsgAnalyzer.can_analyze(s)


def test_healthy_store_summary_and_children():
    s = _analyze(synth.build_unicode_pst_tree())
    r = s.analyzer.reports
    assert r["summary"].data["states"] == {"live": 2}
    assert "recovered_items" not in r and "store_integrity" not in r
    names = [c.filename for c in s.analyzer.childitems]
    assert "invoice.pdf" in names
    assert any(n.startswith("body_") for n in names)


def test_recovered_items_reported_and_emitted():
    img = synth.build_unicode_pst_tree(hard_deleted=True, slack_deleted=True,
                                       superseded=True, moved=True)
    s = _analyze(img)
    rec = s.analyzer.reports["recovered_items"]
    assert rec.severity == Severity.MEDIUM
    states = sorted(d["state"] for d in rec.data)
    assert states == ["deleted", "deleted", "superseded"]
    hard = next(d for d in rec.data if d["subject"] == "Hard deleted")
    assert hard["deletion"]["kind"] == "hard"
    assert hard["deletion"]["deleted_on"] is None
    assert hard["deletion"]["not_before_source"] == "PidTagMessageDeliveryTime"
    names = [c.filename for c in s.analyzer.childitems]
    assert any(n.startswith("deleted_body_") for n in names)


def test_wiped_header_flagged_high_and_still_read():
    img = bytearray(synth.build_unicode_pst_tree())
    img[0:0x400] = b"\x00" * 0x400
    s = Structure.create(data=bytes(img), filename="wiped.pst",
                         mime_type="application/vnd.ms-outlook-pst")
    r = s.analyzer.reports
    assert r["store_integrity"].severity == Severity.HIGH
    assert r["summary"].data["states"] == {"live_damaged": 2}


def test_max_file_size_parser():
    import matt
    assert matt._parse_size("8G") == 8 << 30
    assert matt._parse_size("512m") == 512 << 20
    assert matt._parse_size("1048576") == 1 << 20


def test_matt_logging_controls_library_verbosity():
    import logging
    from Utils.logger import setup_logging
    setup_logging(verbosity=0)
    assert logging.getLogger("pstforensic").level == logging.WARNING
    setup_logging(debug=True)
    lib = logging.getLogger("pstforensic")
    assert lib.level == logging.DEBUG
    assert set(logging.getLogger("matt").handlers) <= set(lib.handlers)
    setup_logging(verbosity=0)


def test_diagnostics_report_attached():
    s = _analyze(synth.build_unicode_pst_tree())
    d = s.analyzer.reports["pst_diagnostics"]
    assert d.data["environment"]["pstforensic"]
    assert d.data["failures"] == []
