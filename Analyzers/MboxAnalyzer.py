import logging
import mailbox
import os
import tempfile
from email import policy

from structure import Analyzer


class MboxAnalyzer(Analyzer):
    compatible_mime_types = ['application/mbox']
    description = "Mbox mailbox analyzer"

    def analysis(self):
        super().analysis()
        mailbox_path = None
        temp_path = None

        try:
            if self.struct.filename and os.path.isfile(self.struct.filename):
                mailbox_path = self.struct.filename
            else:
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(self.struct.rawdata)
                    temp_path = temp_file.name
                mailbox_path = temp_path

            mbox = mailbox.mbox(mailbox_path, factory=None, create=False)
            try:
                for idx, message in enumerate(mbox):
                    try:
                        data = message.as_bytes(policy=policy.default)
                    except Exception:
                        data = message.as_bytes()
                    filename = f"mbox-message-{idx + 1}.eml"
                    self.childitems.append(
                        self.generate_struct(data=data, filename=filename, index=idx)
                    )
            finally:
                mbox.close()
        except (mailbox.NoSuchMailboxError, FileNotFoundError) as exc:
            logging.error(f"Mbox mailbox could not be opened: {exc}")
        finally:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
