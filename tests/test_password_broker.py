import unittest
import importlib
from unittest.mock import patch

from Utils.password_broker import PasswordBroker
from Analyzers.ZipAnalyzer import ZipAnalyzer

zip_analyzer_module = importlib.import_module("Analyzers.ZipAnalyzer")


class _DummyAnalyzer:
    def __init__(self):
        self.reports = {}


class _DummyStruct:
    def __init__(self, rawdata=b"", filename="dummy.bin"):
        self.rawdata = rawdata
        self.filename = filename
        self.analyzer = _DummyAnalyzer()


class PasswordBrokerTests(unittest.TestCase):
    def setUp(self):
        PasswordBroker.clear()

    def tearDown(self):
        PasswordBroker.clear()

    def test_pending_then_password_unlocks_and_adds_source_report(self):
        pending_struct = _DummyStruct(filename="locked.zip")
        source_struct = _DummyStruct(filename="body.txt")
        tries = []

        def try_password(password):
            tries.append(password)
            return password == "secret"

        resolved = PasswordBroker.register_pending(
            struct=pending_struct,
            description="locked.zip (encrypted zip)",
            try_password_cb=try_password,
        )

        self.assertFalse(resolved)
        self.assertEqual(1, len(PasswordBroker._pending))

        PasswordBroker.register_password("secret", source_struct=source_struct)

        self.assertIn("secret", tries)
        self.assertEqual(0, len(PasswordBroker._pending))
        self.assertTrue(
            any(k.startswith("pw_unlock_") for k in source_struct.analyzer.reports)
        )


class ZipAnalyzerRetryTests(unittest.TestCase):
    def _make_zip_analyzer(self):
        analyzer = ZipAnalyzer.__new__(ZipAnalyzer)
        analyzer.struct = _DummyStruct(rawdata=b"PK\x03\x04...", filename="sample.zip")
        analyzer.reports = {}
        analyzer.childitems = []
        analyzer._extracted_members = set()
        return analyzer

    def test_retry_with_password_success_sets_report_and_extracts(self):
        analyzer = self._make_zip_analyzer()
        extract_calls = []
        analyzer._extract_contents = lambda zip_file: extract_calls.append(True)

        class _FakeZipFile:
            def __init__(self, *_args, **_kwargs):
                self._password = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def setpassword(self, password_bytes):
                self._password = password_bytes

            def testzip(self):
                if self._password != b"secret":
                    raise RuntimeError("Bad password for file")

        with patch.object(zip_analyzer_module.zipfile, "ZipFile", _FakeZipFile):
            ok = analyzer._retry_with_password("secret")

        self.assertTrue(ok)
        self.assertIn("password_discovered", analyzer.reports)
        self.assertEqual(1, len(extract_calls))

    def test_retry_with_password_failure_returns_false(self):
        analyzer = self._make_zip_analyzer()

        class _FakeZipFile:
            def __init__(self, *_args, **_kwargs):
                self._password = None

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def setpassword(self, password_bytes):
                self._password = password_bytes

            def testzip(self):
                raise RuntimeError("Bad password for file")

        with patch.object(zip_analyzer_module.zipfile, "ZipFile", _FakeZipFile):
            ok = analyzer._retry_with_password("wrong")

        self.assertFalse(ok)
        self.assertNotIn("password_discovered", analyzer.reports)


if __name__ == "__main__":
    unittest.main()
