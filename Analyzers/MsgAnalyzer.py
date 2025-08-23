import logging
from .base import BaseAnalyzer, Report
import tempfile
import os

try:
    import extract_msg
except ImportError:
    extract_msg = None

class MsgAnalyzer(BaseAnalyzer):
    compatible_mime_types = ['application/vnd.ms-outlook']
    description = "MSG Email Analyzer"
    pip_dependencies = ['extract-msg']

    def analysis(self):
        super().analysis()
        if not extract_msg:
            logging.warning("extract-msg is not installed, cannot analyze MSG files.")
            return

        # extract-msg works with files, so we need to write the data to a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(self.struct.rawdata)
            tmp_path = tmp.name

        try:
            with extract_msg.Message(tmp_path) as msg:
                self.info = msg.subject
                summary = f"From   : {msg.sender}\n"
                summary += f"To     : {msg.to}\n"
                summary += f"Date   : {msg.date}\n"
                summary += f"Subject: {msg.subject}\n"
                self.reports['summary'] = Report(summary)

                if msg.body:
                    self.childitems.append(self.generate_struct(data=msg.body.encode(), filename='email_body.txt', mime_type='text/plain'))

                if msg.htmlBody:
                    # The HTML body in extract-msg is bytes, so no need to encode
                    self.childitems.append(self.generate_struct(data=msg.htmlBody, filename='email_body.html', mime_type='text/html'))

                for idx, attachment in enumerate(msg.attachments):
                    data = attachment.data
                    filename = attachment.longFilename or attachment.shortFilename
                    self.childitems.append(self.generate_struct(data=data, filename=filename, index=idx))
        except Exception as e:
            logging.error(f"Failed to parse MSG file: {e}")
        finally:
            os.remove(tmp_path)
