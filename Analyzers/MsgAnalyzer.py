from structure import Analyzer, Report
import logging
import extract_msg

class MsgAnalyzer(Analyzer):
    compatible_mime_types = ['application/vnd.ms-outlook', 'application/octet-stream']
    description = "MSG Email Analyzer"

    def parse_msg(self):
        try:
            with extract_msg.Message(self.struct.filename) as msg:
                # Extract basic information
                self.info = msg.subject
                summary = f"From   : {msg.sender}\n"
                summary += f"To     : {msg.to}\n"  # Assuming msg.to returns a list
                summary += f"Date   : {msg.date}\n"
                summary += f"Subject: {msg.subject}\n"
                self.reports['summary'] = Report(summary)

                # Extract the email body
                if msg.body:
                    self.childitems.append(self.generate_struct(data=msg.body.encode(), filename='email_body.txt', mime_type='text/plain'))
                if msg.htmlBody:
                    self.childitems.append(self.generate_struct(data=msg.htmlBody.encode(), filename='email_body.html', mime_type='text/html'))

        except Exception as e:
            logging.error(f"Failed to parse MSG file: {e}")
            return

    def extract_parts(self):
        # Assuming the msg object is still accessible or stored, extract attachments
        try:
            with extract_msg.Message(self.struct.filename) as msg:
                for idx, attachment in enumerate(msg.attachments):
                    # Extract attachment data
                    data = attachment.data
                    filename = attachment.longFilename or attachment.shortFilename
                    # Generate a structure for each attachment
                    self.childitems.append(self.generate_struct(data=data, filename=filename, mime_type=None, index=idx))  # MIME type might need to be inferred or set appropriately

        except Exception as e:
            logging.error(f"Error extracting parts from MSG file: {e}")

    def analysis(self):
        self.parse_msg()
        self.extract_parts()
