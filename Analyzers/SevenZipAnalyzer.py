import logging
import tempfile
import os
import lzma
from .base import BaseAnalyzer, Report

try:
    import py7zr
except ImportError:
    py7zr = None

class SevenZipAnalyzer(BaseAnalyzer):
    compatible_mime_types = ['application/x-7z-compressed']
    description = "7Z-File analyser"
    pip_dependencies = ['py7zr']
    passwords = ["infected","Infected","iNFECTED","INFECTED"] # Add more common passwords if needed

    def analysis(self):
        super().analysis()
        if not py7zr:
            logging.warning("py7zr is not installed, cannot analyze 7z files.")
            return

        tmpfile = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmpfile.write(self.struct.rawdata)
            tmpfile.close()

            password_protected = False
            try:
                with py7zr.SevenZipFile(tmpfile.name, 'r') as archive:
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
                self.try_passwords(tmpfile.name)

        finally:
            os.remove(tmpfile.name)

    def try_passwords(self, filepath):
        for password in self.passwords:
            try:
                with py7zr.SevenZipFile(filepath, 'r', password=password.encode()) as archive:
                    self.reports['password'] = Report(password)
                    self.extract_files(archive)
                    return # Exit after first successful password
            except lzma.LZMAError:
                logging.debug(f"Wrong password for 7z file: {password}")
            except py7zr.exceptions.Bad7zFile:
                 logging.warning(f"Bad 7z file with password {password}, could not open.")
                 return
        logging.warning("Could not guess password for 7z file.")

    def extract_files(self, archive):
        try:
            all_files = archive.readall()
            for filename, bio in all_files.items():
                self.childitems.append(self.generate_struct(filename=filename, data=bio.read()))

            filelist = [f.filename for f in archive.list()]
            self.info = f'{len(filelist)} compressed file(s)'
            self.reports['summary'] = Report('\n'.join(filelist))
        except Exception as e:
            logging.error(f"Failed to extract files from 7z archive: {e}")

