import base64
import unittest
from unittest.mock import patch

from Config.config import flags
from structure import Structure
from Utils.password_broker import PasswordBroker
from Utils.plaintext_triage import classify_plaintext


class PlainTextTriageTests(unittest.TestCase):
    def setUp(self):
        Structure.clear_cache()
        PasswordBroker.clear()
        self._saved_flags = {
            "plaintext_external_tools_enabled": flags.plaintext_external_tools_enabled,
            "plaintext_encoded_min_bytes": flags.plaintext_encoded_min_bytes,
            "plaintext_language_max_chars": flags.plaintext_language_max_chars,
            "plaintext_full_scan_bytes": flags.plaintext_full_scan_bytes,
        }
        flags.plaintext_external_tools_enabled = False

    def tearDown(self):
        for key, value in self._saved_flags.items():
            setattr(flags, key, value)
        Structure.clear_cache()
        PasswordBroker.clear()

    def test_large_base64_payload_creates_decoded_child_and_skips_language(self):
        payload = b"MZ" + b"\x00" * 8190
        encoded = base64.encodebytes(payload)

        struct = Structure.create(
            data=encoded,
            filename="payload.txt",
            mime_type="text/plain",
        )

        analyzer = struct.analyzer
        self.assertEqual("encoded_base64", analyzer.profile.kind)
        self.assertIn("decoded_base64_child", analyzer.reports)
        self.assertIn("language_skipped", analyzer.reports)
        self.assertNotIn("language", analyzer.reports)

        children = struct.get_children()
        self.assertEqual(1, len(children))
        self.assertEqual(payload, children[0].rawdata)

    def test_prose_is_not_misclassified_as_base64(self):
        text = (
            "This invoice message contains normal words and punctuation. "
            "The recipient should read it as prose, not encoded data. "
        ) * 100

        profile = classify_plaintext(text.encode("utf-8"), text)

        self.assertNotEqual("encoded_base64", profile.kind)
        self.assertIsNone(profile.decoded_base64)

    def test_high_confidence_password_hint_registers_with_broker_quietly(self):
        text = "Hello, the password for the invoice archive is S3cret-2026. Regards."

        Structure.create(data=text.encode("utf-8"), filename="body.txt", mime_type="text/plain")

        self.assertIn("S3cret-2026", PasswordBroker.get_passwords())

    def test_ioc_password_like_matches_are_not_registered_without_strong_phrase(self):
        text = "Observed token passwordish-value in script output without an unlock phrase."

        Structure.create(data=text.encode("utf-8"), filename="body.txt", mime_type="text/plain")

        self.assertEqual([], PasswordBroker.get_passwords())

    def test_script_like_text_skips_language_detection(self):
        text = "@echo off\r\nset PAYLOAD=abc\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass\r\n"

        struct = Structure.create(
            data=text.encode("utf-8"),
            filename="run.cmd",
            mime_type="text/plain",
        )

        self.assertEqual("script_batch", struct.analyzer.profile.kind)
        self.assertIn("language_skipped", struct.analyzer.reports)
        self.assertNotIn("language", struct.analyzer.reports)

    def test_large_generic_text_uses_bounded_scan_text(self):
        flags.plaintext_language_max_chars = 100
        text = ("AAAA BBBB CCCC DDDD\n" * 70000) + "password: FinalSecret"

        struct = Structure.create(
            data=text.encode("utf-8"),
            filename="large.txt",
            mime_type="text/plain",
        )

        self.assertLessEqual(len(struct.analyzer.scan_text), flags.plaintext_sample_bytes)
        self.assertNotIn("FinalSecret", PasswordBroker.get_passwords())

    def test_language_detector_not_called_for_base64_payload(self):
        payload = b"MZ" + b"\x00" * 8190
        encoded = base64.encodebytes(payload)

        with patch("Analyzers.PlainTextAnalyzer._get_lingua_detector", create=True) as detector:
            Structure.create(data=encoded, filename="payload.txt", mime_type="text/plain")

        detector.assert_not_called()


if __name__ == "__main__":
    unittest.main()
