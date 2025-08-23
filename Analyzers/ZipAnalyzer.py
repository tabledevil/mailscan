import logging
import zipfile
import io
from .base import BaseAnalyzer, Report

class ZipAnalyzer(BaseAnalyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"
    passwords = ["infected", "Infected", "iNFECTED", "INFECTED"]

    def analysis(self):
        super().analysis()
        file_like_object = io.BytesIO(self.struct.rawdata)

        try:
            with zipfile.ZipFile(file_like_object) as zip_file:
                self.info = f'{len(zip_file.infolist())} compressed file(s)'
                filelist = [f'{f.filename} {("<encrypted>" if f.is_encrypted() else "")} [{f.file_size}]' for f in zip_file.infolist()]
                self.reports['summary'] = Report("\n".join(filelist))

                is_encrypted = any(f.is_encrypted() for f in zip_file.infolist())

                if is_encrypted:
                    self.reports['encrypted'] = Report("ZIP File is Password protected")
                    password_found = self._test_passwords(zip_file)
                    if not password_found:
                        logging.warning("Could not find password for encrypted ZIP file.")
                        return # Stop if encrypted and no password works

                # If not encrypted, or if password was found, extract files
                for idx, file_info in enumerate(zip_file.infolist()):
                    try:
                        file_data = zip_file.read(file_info.filename)
                        self.childitems.append(self.generate_struct(filename=file_info.filename, data=file_data, index=idx))
                    except RuntimeError as e:
                        logging.error(f"Could not extract {file_info.filename} from zip: {e}")

        except zipfile.BadZipFile:
            logging.error("Bad ZIP file.")
            self.reports['error'] = Report("Bad ZIP file.")

    def _test_passwords(self, zip_file):
        for password in self.passwords:
            try:
                zip_file.setpassword(password.encode('utf-8'))
                zip_file.testzip() # Test if password is correct for all files
                self.reports['password'] = Report(password)
                return True
            except RuntimeError as e:
                if 'Bad password' in str(e):
                    continue # Try next password
                else:
                    logging.error(f"Error testing password on ZIP file: {e}")
                    return False # Stop on other errors
        return False
