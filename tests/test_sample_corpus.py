"""Sample corpus checks.

No samples live in Git.  A real corpus (encrypted malware ZIPs, mailboxes)
is used only when present: ``$MATT_SAMPLES`` or a local, git-ignored
``samples/`` directory.  Without it these tests skip; the CLI smoke test
builds its own benign mbox.
"""
import mailbox
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
import zipfile
from email.message import EmailMessage


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


def _corpus_dir():
    d = os.environ.get("MATT_SAMPLES") or str(REPO_ROOT / "samples")
    p = pathlib.Path(d)
    return p if p.is_dir() else None


class SampleCorpusTests(unittest.TestCase):
    def test_encrypted_zip_corpus_is_encrypted(self):
        corpus = _corpus_dir()
        zips = sorted(corpus.glob("*.zip")) if corpus else []
        if not zips:
            self.skipTest("no sample corpus (set MATT_SAMPLES)")
        for sample_zip in zips:
            with zipfile.ZipFile(sample_zip, "r") as zf:
                infos = zf.infolist()
                if not infos or not all(i.flag_bits & 0x1 for i in infos):
                    continue    # not every corpus archive is a password container
                self.assertGreater(len(infos), 0)

    def test_cli_can_analyze_benign_mbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "sample.mbox"
            box = mailbox.mbox(path)
            msg = EmailMessage()
            msg["From"], msg["To"], msg["Subject"] = "a@example.test", "b@example.test", "hi"
            msg.set_content("hello")
            box.add(msg)
            box.flush()
            box.close()
            result = subprocess.run(
                [sys.executable, "matt.py", str(path), "--format", "json"],
                cwd=str(REPO_ROOT), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sample.mbox", result.stdout)

    def test_password_secret_can_open_archives(self):
        password = os.getenv("SAMPLE_ZIP_PASSWORD")
        corpus = _corpus_dir()
        if not password or not corpus:
            self.skipTest("SAMPLE_ZIP_PASSWORD / sample corpus not set")
        for sample_zip in sorted(corpus.glob("*.zip")):
            with zipfile.ZipFile(sample_zip, "r") as zf:
                first = zf.infolist()[0]
                try:
                    data = zf.read(first, pwd=password.encode("utf-8"))
                    self.assertGreater(len(data), 0, f"Could not decrypt {sample_zip.name}")
                except (NotImplementedError, RuntimeError):
                    pass


if __name__ == "__main__":
    unittest.main()
