"""Sprint 7 — C2: capability hints when YARA/VT not configured."""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure
from Config.config import flags
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    # Save & restore relevant env / flags
    saved_dir = flags.yara_rules_dir
    saved_key = flags.vt_api_key
    saved_env_key = os.environ.pop("VT_API_KEY", None)
    saved_env_key2 = os.environ.pop("VIRUSTOTAL_API_KEY", None)
    flags.yara_rules_dir = None
    flags.vt_api_key = None
    yield
    flags.yara_rules_dir = saved_dir
    flags.vt_api_key = saved_key
    if saved_env_key is not None:
        os.environ["VT_API_KEY"] = saved_env_key
    if saved_env_key2 is not None:
        os.environ["VIRUSTOTAL_API_KEY"] = saved_env_key2
    Structure.clear_cache()
    PasswordBroker.clear()


def _eml() -> bytes:
    return b"From: a@x.example\r\nTo: b@x.example\r\nSubject: t\r\n\r\nbody\n"


def test_emits_yara_skip_hint_when_no_rules_dir():
    s = Structure.create(data=_eml(), filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("capability_hints")
    assert rep is not None, f"reports: {list(s.analyzer.reports)}"
    assert "YARA" in rep.text


def test_emits_vt_skip_hint_when_no_api_key():
    s = Structure.create(data=_eml(), filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports["capability_hints"]
    assert "VirusTotal" in rep.text


def test_no_yara_hint_when_rules_dir_set(tmp_path):
    flags.yara_rules_dir = str(tmp_path)
    s = Structure.create(data=_eml(), filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("capability_hints")
    if rep is None:
        return  # all configured — no hint at all is fine
    assert "YARA" not in rep.text


def test_no_vt_hint_when_env_var_set(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "fake")
    s = Structure.create(data=_eml(), filename="t.eml", mime_type="message/rfc822")
    rep = s.analyzer.reports.get("capability_hints")
    if rep is None:
        return
    assert "VirusTotal" not in rep.text


def test_capability_hints_only_at_root():
    """A child Structure (level>0) shouldn't carry its own capability hints."""
    s = Structure.create(data=_eml(), filename="t.eml", mime_type="message/rfc822")
    for child in s.get_children():
        assert "capability_hints" not in child.analyzer.reports
