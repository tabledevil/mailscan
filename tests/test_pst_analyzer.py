import importlib
import unittest
from email.parser import BytesParser
from email import policy

from structure import Analyzer, Structure
from Analyzers.PstAnalyzer import PstAnalyzer

pst_module = importlib.import_module("Analyzers.PstAnalyzer")
mailbox_sources = importlib.import_module("Utils.mailbox_sources")


class FakeStruct:
    def __init__(self, filename="sample.pst", rawdata=b"!BDN fake pst"):
        self.filename = filename
        self.rawdata = rawdata


class FakeMessage:
    subject = "Recovered Subject"
    sender_name = "Alice"
    sender_email_address = "alice@example.test"
    display_to = "bob@example.test"
    display_cc = None
    display_bcc = None
    delivery_time = None
    transport_headers = None
    plain_text_body = "Recovered body"
    html_body = None
    rtf_body = None
    number_of_attachments = 0


class FakeFolder:
    name = "Inbox"
    number_of_sub_messages = 1
    number_of_sub_folders = 0

    def get_sub_message(self, idx):
        if idx != 0:
            raise IndexError(idx)
        message = FakeMessage()
        message.subject = "Live Subject"
        message.plain_text_body = "Live body"
        return message


class FakePffFile:
    number_of_orphan_items = 1
    number_of_recovered_items = 1

    def open(self, _path):
        pass

    def close(self):
        pass

    def get_root_folder(self):
        return FakeFolder()

    def get_orphan_item(self, idx):
        if idx != 0:
            raise IndexError(idx)
        message = FakeMessage()
        message.subject = "Orphan Subject"
        message.plain_text_body = "Orphan body"
        return message

    def get_recovered_item(self, idx):
        if idx != 0:
            raise IndexError(idx)
        message = FakeMessage()
        message.subject = "Recovered Subject"
        message.plain_text_body = "Recovered body"
        return message


class FakePypff:
    @staticmethod
    def file():
        return FakePffFile()


class PstAnalyzerTests(unittest.TestCase):
    def tearDown(self):
        Structure.clear_cache()

    def test_pst_claims_pst_signature_and_extension(self):
        self.assertTrue(PstAnalyzer.can_handle(FakeStruct(rawdata=b"!BDN data")))
        self.assertTrue(PstAnalyzer.can_handle(FakeStruct(filename="case.pst", rawdata=b"xxxx")))
        self.assertFalse(PstAnalyzer.can_handle(FakeStruct(filename="mail.msg", rawdata=b"xxxx")))

    def test_ambiguous_octet_stream_dispatches_to_pst(self):
        analyzer = Analyzer.get_analyzer("application/octet-stream", FakeStruct())
        self.assertIs(analyzer, PstAnalyzer)

    def test_recovered_and_orphan_items_are_extracted_and_marked(self):
        original_pypff = pst_module.pypff
        original_sources_pypff = mailbox_sources.pypff
        pst_module.pypff = FakePypff
        mailbox_sources.pypff = FakePypff
        try:
            struct = Structure.create(
                data=b"!BDN fake pst",
                filename="sample.pst",
                mime_type="application/vnd.ms-outlook-pst",
            )
        finally:
            pst_module.pypff = original_pypff
            mailbox_sources.pypff = original_sources_pypff

        children = struct.get_children()
        self.assertEqual(3, len(children))
        recovered_messages = [
            BytesParser(policy=policy.default).parsebytes(child.rawdata)
            for child in children
            if child.filename.startswith("pst-recovered-message")
        ]
        self.assertEqual(2, len(recovered_messages))
        self.assertTrue(all(msg["X-MATT-PST-Recovered"] == "true" for msg in recovered_messages))
        self.assertTrue(all(msg["X-MATT-PST-Folder"] for msg in recovered_messages))
        self.assertIn("recovered/orphan message(s): 2", struct.analyzer.reports["messages"].text)


if __name__ == "__main__":
    unittest.main()
