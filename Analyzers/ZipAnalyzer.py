import logging
import zipfile
import io
from structure import Analyzer, Report
from Config.config import flags

try:
    import pyzipper
except ImportError:
    pyzipper = None

class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"
    passwords = ["infected", "Infected", "iNFECTED", "INFECTED"]

    # Add pyzipper as optional dependency for AES support
    optional_pip_dependencies = [('pyzipper', 'pyzipper')]

    def analysis(self):
        super().analysis()
        file_like_object = io.BytesIO(self.struct.rawdata)

        # Merge shared passwords from context
        if hasattr(self.struct, 'context') and self.struct.context and 'passwords' in self.struct.context:
             # Add context passwords to local list if not present, preserving order
             for pwd in self.struct.context['passwords']:
                 if pwd not in self.passwords:
                     self.passwords.append(pwd)

        # Use pyzipper if available for better encryption support
        zip_class = pyzipper.AESZipFile if pyzipper else zipfile.ZipFile

        try:
            with zip_class(file_like_object) as zip_file:
                self.info = f'{len(zip_file.infolist())} compressed file(s)'
                filelist = [f'{f.filename} {("<encrypted>" if f.flag_bits & 0x1 else "")} [{f.file_size}]' for f in zip_file.infolist()]
                self.reports['summary'] = Report("\n".join(filelist))

                # Zip bomb checks
                total_uncompressed_size = sum(f.file_size for f in zip_file.infolist())
                if self.struct.size > 0 and total_uncompressed_size / self.struct.size > flags.max_compression_ratio:
                    logging.warning("Zip bomb detected: compression ratio too high.")
                    self.reports['error'] = Report("Zip bomb detected: compression ratio too high.")
                    return

                if total_uncompressed_size > flags.max_file_size:
                    logging.warning("Zip bomb detected: total uncompressed size is too large.")
                    self.reports['error'] = Report("Zip bomb detected: total uncompressed size is too large.")
                    return

                is_encrypted = any(f.flag_bits & 0x1 for f in zip_file.infolist())

                if is_encrypted:
                    self.reports['encrypted'] = Report("ZIP File is Password protected")
                    password_found = self._test_passwords(zip_file)
                    if not password_found:
                        logging.warning("Could not find password for encrypted ZIP file.")
                        if not pyzipper:
                             logging.warning("Install 'pyzipper' to support AES encrypted ZIP files.")
                        return # Stop if encrypted and no password works

                # If not encrypted, or if password was found, extract files
                for idx, file_info in enumerate(zip_file.infolist()):
                    try:
                        file_data = zip_file.read(file_info.filename)
                        self.childitems.append(self.generate_struct(filename=file_info.filename, data=file_data, index=idx))
                    except RuntimeError as e:
                        logging.error(f"Could not extract {file_info.filename} from zip: {e}")
                    except Exception as e:
                        logging.error(f"Error extracting {file_info.filename}: {e}")

        except zipfile.BadZipFile:
            logging.error("Bad ZIP file.")
            self.reports['error'] = Report("Bad ZIP file.")
        except Exception as e:
            logging.error(f"Error processing ZIP file: {e}")

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
                    logging.debug(f"Error testing password on ZIP file: {e}")
                    continue
            except Exception as e:
                logging.debug(f"Error testing password on ZIP file: {e}")
                continue
        return False
