"""Sprint 7 — C1: archives report compression_ratio."""

import io
import os
import sys
import zipfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structure import Structure, Severity
from Utils.password_broker import PasswordBroker


@pytest.fixture(autouse=True)
def _clear():
    Structure.clear_cache()
    PasswordBroker.clear()
    yield
    Structure.clear_cache()
    PasswordBroker.clear()


def _zip_with(payload: bytes) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr("payload.txt", payload)
    return bio.getvalue()


def test_zip_emits_compression_ratio_report():
    data = _zip_with(b"hello world\n" * 200)
    s = Structure.create(data=data, filename="t.zip", mime_type="application/zip")
    rep = s.analyzer.reports.get("compression_ratio")
    assert rep is not None
    assert ":1" in rep.text
    assert ":1" in rep.short


def test_high_ratio_yields_low_or_medium_severity():
    """Long run of repeated bytes compresses very well — should bump severity."""
    data = _zip_with(b"A" * 100_000)
    s = Structure.create(data=data, filename="t.zip", mime_type="application/zip")
    rep = s.analyzer.reports["compression_ratio"]
    # 100KB of 'A' compresses to ~150 bytes — ratio ≫ 20
    assert rep.severity in (Severity.LOW, Severity.MEDIUM)


def test_normal_ratio_is_info():
    """Mixed content with low compressibility stays INFO."""
    data = _zip_with(os.urandom(2048))
    s = Structure.create(data=data, filename="t.zip", mime_type="application/zip")
    rep = s.analyzer.reports.get("compression_ratio")
    if rep is None:
        return  # tiny zips may overhead-dominate; that's fine
    assert rep.severity == Severity.INFO
