"""Sprint 8 — QRAnalyzer: decode QR codes embedded in image attachments.

The integration tests need a working ``pyzbar`` + libzbar shared lib;
they are skipped when the lib is unavailable. The behavioural tests
(graceful degradation, registration, MIME compatibility) run regardless.
"""

import io
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
# Behavioural tests — run regardless of zbar availability
# ---------------------------------------------------------------


def test_qr_analyzer_is_registered():
    from Analyzers import QRAnalyzer  # noqa: F401
    assert QRAnalyzer.compatible_mime_types
    assert "image/png" in QRAnalyzer.compatible_mime_types


def test_qr_analyzer_silent_when_no_qr_in_image():
    """A plain PNG with no QR code should produce no qr_* reports."""
    pytest.importorskip("PIL")
    from PIL import Image

    bio = io.BytesIO()
    Image.new("RGB", (50, 50), color="white").save(bio, format="PNG")
    s = Structure.create(data=bio.getvalue(), filename="x.png",
                         mime_type="image/png")
    qr_keys = [k for k in s.analyzer.reports if k.startswith("qr")]
    # Either pyzbar isn't loaded (no reports possible) or it ran and found
    # nothing — either way the result is "no QR-related reports".
    assert qr_keys == []


# ---------------------------------------------------------------
# Integration — only when pyzbar + libzbar are available
# ---------------------------------------------------------------


def _pyzbar_works() -> bool:
    try:
        from pyzbar import pyzbar  # noqa: F401
        return True
    except (ImportError, OSError):
        return False


@pytest.mark.skipif(not _pyzbar_works(),
                    reason="pyzbar/libzbar not available")
def test_qr_analyzer_decodes_url_qr():
    pytest.importorskip("qrcode")
    import qrcode

    img = qrcode.make("https://malicious.example/login")
    bio = io.BytesIO()
    img.save(bio, format="PNG")

    s = Structure.create(data=bio.getvalue(), filename="qr.png",
                         mime_type="image/png")
    reports = s.analyzer.reports
    assert "qr_summary" in reports, list(reports)
    assert any(k.startswith("qr_") and k != "qr_summary"
               and k != "qr_payload_text"
               for k in reports)
    summary = reports["qr_summary"]
    assert "1" in summary.text  # one barcode decoded
    qr0 = next(reports[k] for k in reports if k.startswith("qr_") and k[3:].isdigit())
    assert "malicious.example" in qr0.text


@pytest.mark.skipif(not _pyzbar_works(),
                    reason="pyzbar/libzbar not available")
def test_qr_payload_propagates_to_root_iocs_aggregate():
    """A URL inside a QR code embedded in an image attachment must surface
    in the root iocs_aggregate (defanged)."""
    pytest.importorskip("qrcode")
    import qrcode

    img = qrcode.make("https://qr-phish.example/path")
    bio = io.BytesIO()
    img.save(bio, format="PNG")

    # Build a multipart eml with the QR PNG attached
    import base64
    png_b64 = base64.b64encode(bio.getvalue()).decode()
    eml = (
        "From: a@a.example\r\nTo: b@b.example\r\nSubject: scan to verify\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nplease scan\r\n"
        "--b\r\nContent-Type: image/png\r\n"
        'Content-Disposition: attachment; filename="qr.png"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
    )
    eml += "\r\n".join(png_b64[i:i+76] for i in range(0, len(png_b64), 76))
    eml += "\r\n--b--\r\n"

    s = Structure.create(data=eml.encode(), filename="t.eml",
                         mime_type="message/rfc822")
    agg = s.analyzer.reports.get("iocs_aggregate")
    assert agg is not None
    assert "qr-phish" in agg.text or "qr\\-phish" in agg.text
