"""QR / barcode decoding analyzer.

Runs on every image and decodes any QR codes / 1D barcodes found via
``pyzbar`` (libzbar). Decoded payloads are reported individually and any
URL/email/IP found in them is fed through the IOC extractor so the
content shows up in the root ``iocs_aggregate``.

Silent when the library is unavailable — this is a contributor analyzer,
not a primary one (specificity 5). When ``pyzbar`` / ``zbar`` is missing,
the tool still works; the optional dep is announced via ``--check`` and
in the root capability_hints report.

QR codes are an increasingly common phishing channel ("scan to verify
your inbox"), so finding one in a mail-attached image is itself an
analyst signal even before the contents are inspected.
"""

from __future__ import annotations

import logging

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

try:
    from PIL import Image as _PILImage
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False

try:
    from pyzbar import pyzbar as _pyzbar
    _PYZBAR_AVAILABLE = True
except (ImportError, OSError):
    # OSError fires when the library imports but libzbar is not on the
    # system — pyzbar raises it at import time.
    _PYZBAR_AVAILABLE = False


# URL/email/IP-like substring sniffers used to grade severity. The full
# IOC extractor will later run on the same payload via the root
# aggregate; here we just need a quick severity hint.
_URL_HINT = ("http://", "https://", "ftp://", "hxxp://", "hxxps://")


def _grade_payload(payload: str) -> Severity:
    """Severity heuristic for a single QR payload."""
    p = payload.lower()
    if any(p.startswith(s) or s in p for s in _URL_HINT):
        return Severity.MEDIUM
    if "@" in p and "." in p.split("@", 1)[-1]:
        # Email or mailto: link
        return Severity.LOW
    if p.startswith(("tel:", "sms:", "geo:", "wifi:", "matmsg:")):
        return Severity.LOW
    return Severity.INFO


class QRAnalyzer(Analyzer):
    """Decode QR codes and 1D barcodes embedded in image attachments."""

    compatible_mime_types = [
        "image/jpeg",
        "image/png",
        "image/tiff",
        "image/gif",
        "image/bmp",
        "image/webp",
    ]
    description = "QR / barcode decoder"
    # Contributor — never the primary analyzer; ImageAnalyzer (specificity
    # 20) stays primary, this just adds findings on top.
    specificity = 5

    optional_pip_dependencies = [("pyzbar", "pyzbar")]
    optional_system_dependencies = ["zbar"]
    extra = "qr"

    @classmethod
    def can_handle(cls, struct) -> bool:
        # Compatible MIMEs already accepted; this analyzer does not need to
        # speculate beyond that.
        return False

    def analysis(self):
        if not (_PIL_AVAILABLE and _PYZBAR_AVAILABLE):
            log.debug("QRAnalyzer: pyzbar/zbar not available — skipping")
            return

        try:
            from io import BytesIO
            img = _PILImage.open(BytesIO(self.struct.rawdata))
            # Some images are paletted/CMYK; pyzbar prefers L or RGB.
            if img.mode not in ("L", "RGB"):
                img = img.convert("RGB")
            decoded = _pyzbar.decode(img)
        except Exception as e:
            log.debug("QRAnalyzer: decode failed: %s", e)
            return

        if not decoded:
            return  # Silent on no findings, per spec.

        # Emit one report per decoded payload, plus an aggregate summary.
        worst = Severity.INFO
        payloads = []
        for idx, sym in enumerate(decoded):
            try:
                payload = sym.data.decode("utf-8", errors="replace")
            except Exception:
                continue
            sym_type = getattr(sym, "type", "QRCODE") or "QRCODE"
            sev = _grade_payload(payload)
            worst = min(worst, sev)
            payloads.append((sym_type, payload))
            self.reports[f"qr_{idx}"] = Report(
                f"{sym_type}: {payload}",
                short=f"{sym_type}: {payload[:80]}",
                label=f"qr_code_{idx}",
                severity=sev,
                verbosity=0,
                order=22,
                data={"type": sym_type, "payload": payload},
            )

        # Promote to a single labelled finding so renderers can headline it.
        labels = sorted({t for t, _ in payloads})
        self.reports["qr_summary"] = Report(
            f"{len(payloads)} barcode(s) decoded ({', '.join(labels)})",
            short=f"{len(payloads)} QR/barcode(s)",
            label="qr_summary",
            severity=worst,
            verbosity=0,
            order=21,
            data={"count": len(payloads),
                  "payloads": [{"type": t, "payload": p} for t, p in payloads]},
        )

        # Push payload text into the IOC pipeline by attaching a
        # synthesised text/plain Report — _build_ioc_aggregate harvests
        # `report.text` from every node, so URLs/emails inside QR codes
        # will land in the root iocs_aggregate automatically.
        joined = "\n".join(f"{t}: {p}" for t, p in payloads)
        self.reports["qr_payload_text"] = Report(
            joined,
            label="qr_payloads",
            severity=Severity.INFO,
            verbosity=2,  # hidden from default display — feeder for IOCs
            order=99,
        )
