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

    # -- PST/OST via pstforensic ------------------------------------------
    def _make_pst(self, directory):
        from pstforensic.tests import synth
        path = pathlib.Path(directory) / "box.pst"
        path.write_bytes(synth.build_unicode_pst_tree(hard_deleted=True))
        return path

    def test_pst_records_include_recovered_items(self):
        from Utils.mailbox_sources import iter_mail_records
        with tempfile.TemporaryDirectory() as tmp:
            recs = list(iter_mail_records([str(self._make_pst(tmp))]))
            live_only = list(iter_mail_records([str(self._make_pst(tmp))],
                                               include_pst_recovered=False))
        self.assertEqual(["live", "live", "deleted"], [r.state for r in recs])
        self.assertTrue(recs[2].recovered)
        self.assertEqual("true", recs[2].parse()["X-MATT-PST-Recovered"])
        self.assertEqual(2, len(live_only))
        self.assertFalse(any(r.error for r in recs))

    def test_hunt_finds_sender_in_pst(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._make_pst(tmp)
            output = self._run(["hunt", "-q", "evil.example", str(path)])
            hashes = self._run(["attachments", str(path)])
        self.assertIn("box.pst#3", output)
        self.assertIn("recovered=true", output)
        self.assertIn("invoice.pdf", hashes)


if __name__ == "__main__":
    unittest.main()
