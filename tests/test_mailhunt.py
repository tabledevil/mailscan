import contextlib
from email.message import EmailMessage
import hashlib
import io
import mailbox
import pathlib
import tempfile
import unittest

import mailhunt


class MailhuntTests(unittest.TestCase):
    def _make_message(self):
        msg = EmailMessage()
        msg["From"] = "alice@example.test"
        msg["To"] = "bob@example.test"
        msg["Subject"] = "Investigation bad.example"
        msg.set_content("Visit https://bad.example/path for details")
        data = b"payload with marker"
        msg.add_attachment(data, maintype="application", subtype="octet-stream", filename="invoice.bin")
        return msg, data

    def _make_mbox(self, directory):
        path = pathlib.Path(directory) / "sample.mbox"
        box = mailbox.mbox(path)
        msg, data = self._make_message()
        box.add(msg)
        box.flush()
        box.close()
        return path, data

    def _run(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = mailhunt.main(argv)
        self.assertEqual(0, code)
        return out.getvalue()

    def test_hunt_finds_domain_in_mbox_body_and_header(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, _data = self._make_mbox(tmp)
            output = self._run(["hunt", "-q", "bad.example", str(path)])
        self.assertIn("sample.mbox#1", output)
        self.assertIn("headers", output)
        self.assertIn("text/plain", output)

    def test_hunt_finds_attachment_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, data = self._make_mbox(tmp)
            digest = hashlib.sha256(data).hexdigest()
            output = self._run(["hunt", "-q", digest, str(path)])
        self.assertIn("attachment", output)
        self.assertIn(digest, output)

    def test_attachment_listing_outputs_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            path, data = self._make_mbox(tmp)
            output = self._run(["attachments", str(path)])
        self.assertIn("invoice.bin", output)
        self.assertIn(hashlib.sha256(data).hexdigest(), output)


if __name__ == "__main__":
    unittest.main()
