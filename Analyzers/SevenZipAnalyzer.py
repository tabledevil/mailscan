import logging
from structure import Analyzer, Report
from Config.config import flags
from Utils.temp_manager import TempFileManager
import lzma
import os

try:
    import py7zr
except ImportError:
    py7zr = None

class SevenZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/x-7z-compressed']
    description = "7Z-File analyser"
    passwords = ["infected", "Infected", "iNFECTED", "INFECTED"]

    # py7zr is required for this analyzer to work at all
    optional_pip_dependencies = [('py7zr', 'py7zr')]
    extra = "7z"

    def analysis(self):
        super().analysis()
        if not py7zr:
            logging.warning("py7zr is not installed, cannot analyze 7z files.")
            return

        # Add shared passwords from context
        local_passwords = list(self.passwords)
        if hasattr(self.struct, 'context') and self.struct.context and 'passwords' in self.struct.context:
             for pwd in self.struct.context['passwords']:
                 if pwd not in local_passwords:
                     local_passwords.append(pwd)

        # DEBUG LOG
        # logging.warning(f"7Z PASSWORDS AVAILABLE: {local_passwords}")

        with TempFileManager() as temp_manager:
            tmp_file_path = temp_manager.create_temp_file(self.struct.rawdata)

            password_protected = False
            try:
                with py7zr.SevenZipFile(tmp_file_path, 'r') as archive:
                    if archive.password_protected:
                        password_protected = True
                    else:
                        self.extract_files(archive)
            except py7zr.exceptions.PasswordRequired:
                password_protected = True
            except py7zr.exceptions.Bad7zFile:
                logging.warning("Bad 7z file, could not open.")
                return

            if password_protected:
                self.try_passwords(tmp_file_path, local_passwords)

    def try_passwords(self, filepath, password_list):
        for password in password_list:
            try:
                with py7zr.SevenZipFile(filepath, 'r', password=password) as archive:
                    self.reports['password'] = Report(password)
                    self.extract_files(archive)
                    return
            except lzma.LZMAError:
                pass
            except py7zr.exceptions.Bad7zFile:
                 pass
            except Exception as e:
                 pass

        logging.warning("Could not guess password for 7z file.")

    def extract_files(self, archive):
        try:
            # Zip bomb checks
            total_uncompressed_size = sum(f.uncompressed for f in archive.list())
            if self.struct.size > 0 and total_uncompressed_size / self.struct.size > flags.max_compression_ratio:
                logging.warning("7z bomb detected: compression ratio too high.")
                self.reports['error'] = Report("7z bomb detected: compression ratio too high.")
                return

            if total_uncompressed_size > flags.max_file_size:
                logging.warning("7z bomb detected: total uncompressed size is too large.")
                self.reports['error'] = Report("7z bomb detected: total uncompressed size is too large.")
                return

            all_files = archive.readall()
            for filename, bio in all_files.items():
                self.childitems.append(self.generate_struct(filename=filename, data=bio.read()))

            filelist = [f.filename for f in archive.list()]
            self.info = f'{len(filelist)} compressed file(s)'
            self.reports['summary'] = Report('\n'.join(filelist))
        except Exception as e:
            logging.error(f"Failed to extract files from 7z archive: {e}")
