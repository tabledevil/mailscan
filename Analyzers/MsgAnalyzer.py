import logging
from .base import BaseAnalyzer, Report
from Utils.temp_manager import TempFileManager

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

        with TempFileManager() as temp_manager:
            tmp_file_path = temp_manager.create_temp_file(self.struct.rawdata)
            try:
                with extract_msg.Message(tmp_file_path) as msg:
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
