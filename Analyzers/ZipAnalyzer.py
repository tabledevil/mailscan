import logging
import zipfile
import io
from structure import Analyzer, Report
from Config.config import flags
from Utils.password_broker import PasswordBroker


class ZipAnalyzer(Analyzer):
    compatible_mime_types = ["application/zip", "application/x-zip-compressed"]
    description = "ZIP-File analyser"
    passwords = ["infected", "Infected", "iNFECTED", "INFECTED"]

    def analysis(self):
        super().analysis()
        self._extracted_members = set()
        file_like_object = io.BytesIO(self.struct.rawdata)

        try:
            with zipfile.ZipFile(file_like_object) as zip_file:
                self.info = f"{len(zip_file.infolist())} compressed file(s)"
                filelist = [
                    f"{f.filename} {('<encrypted>' if f.flag_bits & 0x1 else '')} [{f.file_size}]"
                    for f in zip_file.infolist()
                ]
                self.reports["summary"] = Report("\n".join(filelist))

                # Zip bomb checks
                total_uncompressed_size = sum(f.file_size for f in zip_file.infolist())
                if (
                    self.struct.size > 0
                    and total_uncompressed_size / self.struct.size
                    > flags.max_compression_ratio
                ):
                    logging.warning("Zip bomb detected: compression ratio too high.")
                    self.reports["error"] = Report(
                        "Zip bomb detected: compression ratio too high."
                    )
                    return

                if total_uncompressed_size > flags.max_file_size:
                    logging.warning(
                        "Zip bomb detected: total uncompressed size is too large."
                    )
                    self.reports["error"] = Report(
                        "Zip bomb detected: total uncompressed size is too large."
                    )
                    return

                is_encrypted = any(f.flag_bits & 0x1 for f in zip_file.infolist())

                if is_encrypted:
                    self.reports["encrypted"] = Report("ZIP File is Password protected")
                    password_found = self._test_passwords(zip_file)
                    if not password_found:
                        resolved = PasswordBroker.register_pending(
                            struct=self.struct,
                            description=f"{self.struct.filename} (encrypted zip)",
                            try_password_cb=self._retry_with_password,
                            on_unlock=self._on_unlocked,
                        )
                        if not resolved:
                            self.reports["pending_password"] = Report(
                                "Encrypted ZIP queued for retry when passwords are discovered",
                                label="pending_password",
                                rank=1,
                            )
                            logging.warning(
                                "Could not find password for encrypted ZIP file."
                            )
                            return  # Stop for now, broker will retry later

                # If not encrypted, or if password was found, extract files
                self._extract_contents(zip_file)

        except zipfile.BadZipFile:
            logging.error("Bad ZIP file.")
            self.reports["error"] = Report("Bad ZIP file.")

    def _test_passwords(self, zip_file):
        for password in self.passwords:
            try:
                zip_file.setpassword(password.encode("utf-8"))
                zip_file.testzip()  # Test if password is correct for all files
                self.reports["password"] = Report(password)
                return True
            except RuntimeError as e:
                if "Bad password" in str(e):
                    continue  # Try next password
                else:
                    logging.error(f"Error testing password on ZIP file: {e}")
                    return False  # Stop on other errors
        return False

    def _extract_contents(self, zip_file):
        for idx, file_info in enumerate(zip_file.infolist()):
            member_key = (file_info.filename, file_info.CRC, file_info.file_size)
            if member_key in self._extracted_members:
                continue
            try:
                file_data = zip_file.read(file_info.filename)
                self.childitems.append(
                    self.generate_struct(
                        filename=file_info.filename,
                        data=file_data,
                        index=idx,
                    )
                )
                self._extracted_members.add(member_key)
            except RuntimeError as e:
                logging.error(f"Could not extract {file_info.filename} from zip: {e}")

    def _retry_with_password(self, password):
        file_like_object = io.BytesIO(self.struct.rawdata)
        try:
            with zipfile.ZipFile(file_like_object) as zip_file:
                zip_file.setpassword(password.encode("utf-8"))
                zip_file.testzip()
                self.reports["password_discovered"] = Report(
                    "ZIP unlocked with discovered password",
                    label="password_discovered",
                    rank=1,
                )
                self._extract_contents(zip_file)
                return True
        except (RuntimeError, zipfile.BadZipFile):
            return False

    def _on_unlocked(self, _password, _source_struct):
        self.reports["decrypted"] = Report(
            "Encrypted ZIP decrypted after password discovery",
            label="decrypted",
            rank=1,
        )
