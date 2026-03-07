import os
import pathlib
import subprocess
import sys
import unittest
import zipfile


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTFILES_DIR = REPO_ROOT / "testfiles"


class SampleCorpusTests(unittest.TestCase):
    def test_sample_mbox_exists(self):
        self.assertTrue((TESTFILES_DIR / "sample.mbox").is_file())

    def test_encrypted_zip_corpus_present(self):
        zip_files = sorted(TESTFILES_DIR.glob("*.zip"))
        self.assertGreater(len(zip_files), 0, "No ZIP samples found in testfiles/")

        for sample_zip in zip_files:
            with zipfile.ZipFile(sample_zip, "r") as zf:
                infos = zf.infolist()
                self.assertGreater(len(infos), 0, f"{sample_zip.name} is empty")
                self.assertTrue(
                    all(info.flag_bits & 0x1 for info in infos),
                    f"{sample_zip.name} contains unencrypted entries",
                )

    def test_cli_can_analyze_benign_mbox(self):
        cmd = [sys.executable, "matt.py", "testfiles/sample.mbox", "--format", "json"]
        result = subprocess.run(
            cmd,
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("sample.mbox", result.stdout)

    def test_password_secret_can_open_archives(self):
        password = os.getenv("SAMPLE_ZIP_PASSWORD")
        if not password:
            self.skipTest("SAMPLE_ZIP_PASSWORD is not set")

        for sample_zip in sorted(TESTFILES_DIR.glob("*.zip")):
            with zipfile.ZipFile(sample_zip, "r") as zf:
                first = zf.infolist()[0]
                try:
                    data = zf.read(first, pwd=password.encode("utf-8"))
                    self.assertGreater(len(data), 0, f"Could not decrypt {sample_zip.name}")
                except NotImplementedError:
                    # Skip if compression method is not supported (e.g. AES without support)
                    pass


if __name__ == "__main__":
    unittest.main()
