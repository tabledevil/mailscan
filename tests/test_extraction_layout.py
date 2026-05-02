"""Sprint 8 — extraction layout & manifest."""

import io
import json
import os
import sys
import zipfile

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


def _eml_with_zipped_js() -> bytes:
    """Build an eml with one base64 zipped attachment containing a .JS."""
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("payload.js", b"this.X += 'a';")
    import base64
    z_b64 = base64.b64encode(bio.getvalue()).decode().strip()
    out = (
        "From: a@a.example\r\nTo: b@b.example\r\nSubject: t\r\n"
        "MIME-Version: 1.0\r\n"
        'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        "--b\r\nContent-Type: text/plain\r\n\r\nbody\r\n"
        "--b\r\nContent-Type: application/zip\r\n"
        'Content-Disposition: attachment; filename="dropper.zip"\r\n'
        "Content-Transfer-Encoding: base64\r\n\r\n"
    )
    out += "\r\n".join(z_b64[i:i+76] for i in range(0, len(z_b64), 76))
    out += "\r\n--b--\r\n"
    return out.encode("utf-8")


def test_default_extract_uses_original_filenames(tmp_path):
    s = Structure.create(data=_eml_with_zipped_js(), filename="t.eml",
                         mime_type="message/rfc822")
    s.extract(basepath=str(tmp_path), recursive=True)
    paths = sorted(p.relative_to(tmp_path).as_posix()
                   for p in tmp_path.rglob("*") if p.is_file())
    # Original archive entry name preserved through the hierarchy
    assert any("dropper.zip" in p for p in paths), paths
    assert any("payload.js" in p for p in paths), paths


def test_default_extract_writes_manifest_json(tmp_path):
    s = Structure.create(data=_eml_with_zipped_js(), filename="t.eml",
                         mime_type="message/rfc822")
    s.extract(basepath=str(tmp_path), recursive=True)
    manifest = tmp_path / "manifest.json"
    assert manifest.exists()
    entries = json.loads(manifest.read_text())
    assert isinstance(entries, list) and len(entries) >= 3
    # Every entry must carry full md5/sha1/sha256 + abspath + level + mime
    for e in entries:
        assert e["md5"] and e["sha1"] and e["sha256"]
        assert e["abspath"].startswith("/")
        assert "level" in e
        assert "mime" in e


def test_unfilenamed_part_uses_stable_role_name(tmp_path):
    """Inline body parts (no Content-Disposition filename) used to extract as
    truncated MD5 ('dd6d8e6d.txt'). They should now be 'part_<index>.<ext>'."""
    s = Structure.create(data=_eml_with_zipped_js(), filename="t.eml",
                         mime_type="message/rfc822")
    s.extract(basepath=str(tmp_path), recursive=True)
    names = [p.name for p in tmp_path.rglob("*") if p.is_file()]
    # No truncated-md5 names: hex stem of length 8 immediately followed by ext
    import re
    bad = [n for n in names if re.match(r"^[0-9a-f]{8}\.\w+$", n)]
    assert bad == [], f"truncated-md5 names leaked: {bad}"
    # Stable role name is present
    assert any(n.startswith("part_") for n in names), names


def test_hash_names_mode_still_works(tmp_path):
    s = Structure.create(data=_eml_with_zipped_js(), filename="t.eml",
                         mime_type="message/rfc822")
    s.extract(basepath=str(tmp_path), recursive=True, filenames=False)
    names = [p.name for p in tmp_path.rglob("*") if p.is_file() and p.name != "manifest.json"]
    # In hash-names mode every filename's stem is a 32-char md5
    import re
    for n in names:
        stem = os.path.splitext(n)[0]
        # Allow numbered suffix _N from collision avoidance
        stem_no_suffix = re.sub(r"_\d+$", "", stem)
        assert re.match(r"^[0-9a-f]{32}$", stem_no_suffix), n


def test_no_collision_clobber(tmp_path):
    """Two siblings sharing a sanitized name must not overwrite each other."""
    eml = (
        b"From: a@a.example\r\nTo: b@b.example\r\nSubject: t\r\n"
        b"MIME-Version: 1.0\r\n"
        b'Content-Type: multipart/mixed; boundary="b"\r\n\r\n'
        b"--b\r\nContent-Type: text/plain\r\n"
        b'Content-Disposition: attachment; filename="img.png"\r\n\r\nAAA\r\n'
        b"--b\r\nContent-Type: text/plain\r\n"
        b'Content-Disposition: attachment; filename="img.png"\r\n\r\nBBB\r\n'
        b"--b--\r\n"
    )
    s = Structure.create(data=eml, filename="t.eml", mime_type="message/rfc822")
    s.extract(basepath=str(tmp_path), recursive=True)
    pngs = sorted(p.name for p in tmp_path.rglob("img*"))
    assert len(pngs) >= 2, f"siblings clobbered: {pngs}"
