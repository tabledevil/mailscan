import logging
import io
from structure import Analyzer, Report, Severity
from Config.config import flags
from Utils.password_broker import PasswordBroker

log = logging.getLogger("matt")

try:
    import rarfile
except ImportError:
    rarfile = None


class RARAnalyzer(Analyzer):
    """Analyzer for RAR archive files.

    Extracts contents, tests passwords on encrypted archives,
    detects RAR bombs, and integrates with the PasswordBroker
    for cross-analyzer password discovery.
    """

    compatible_mime_types = [
        "application/x-rar-compressed",
        "application/x-rar",
        "application/vnd.rar",
    ]
    description = "RAR Archive Analyser"
    specificity = 10
    optional_pip_dependencies = [("rarfile", "rarfile")]
    optional_system_dependencies = ["unrar"]
    extra = "rar"

    passwords = ["infected", "Infected", "iNFECTED", "INFECTED"]

    def analysis(self):
        super().analysis()
        if not rarfile:
            log.warning("rarfile is not installed, cannot analyze RAR files.")
            return

        self._extracted_members = set()

        # Add shared passwords from context
        local_passwords = list(self.passwords)
        if hasattr(self.struct, "context") and self.struct.context and "passwords" in self.struct.context:
            for pwd in self.struct.context["passwords"]:
                if pwd not in local_passwords:
                    local_passwords.append(pwd)

        try:
            file_like_object = io.BytesIO(self.struct.rawdata)
            rf = rarfile.RarFile(file_like_object)

            file_list = rf.infolist()
            self.info = f"{len(file_list)} compressed file(s)"

            filelist_display = []
            for f in file_list:
                encrypted_tag = " <encrypted>" if f.needs_password() else ""
                filelist_display.append(
                    f"{f.filename}{encrypted_tag} [{f.file_size}]"
                )
            self.reports["summary"] = Report("\n".join(filelist_display))

            # RAR bomb detection
            total_uncompressed = sum(f.file_size for f in file_list)
            if (
                self.struct.size > 0
                and total_uncompressed / self.struct.size > flags.max_compression_ratio
            ):
                log.warning("RAR bomb detected: compression ratio too high.")
                self.reports["error"] = Report(
                    "RAR bomb detected: compression ratio too high.",
                    severity=Severity.HIGH,
                )
                return

            if total_uncompressed > flags.max_file_size:
                log.warning("RAR bomb detected: total uncompressed size is too large.")
                self.reports["error"] = Report(
                    "RAR bomb detected: total uncompressed size is too large.",
                    severity=Severity.HIGH,
                )
                return

            is_encrypted = any(f.needs_password() for f in file_list)

            if is_encrypted:
                self.reports["encrypted"] = Report(
                    "RAR archive is password protected",
                    severity=Severity.LOW,
                )
                password_found = self._test_passwords(rf, local_passwords)
                if not password_found:
                    resolved = PasswordBroker.register_pending(
                        struct=self.struct,
                        description=f"{self.struct.filename} (encrypted RAR)",
                        try_password_cb=self._retry_with_password,
                        on_unlock=self._on_unlocked,
                    )
                    if not resolved:
                        self.reports["pending_password"] = Report(
                            "Encrypted RAR queued for retry when passwords are discovered",
                            label="pending_password",
                            rank=1,
                        )
                        log.warning("Could not find password for encrypted RAR file.")
                        return
            else:
                self._extract_contents(rf)

            rf.close()

        except rarfile.BadRarFile:
            log.error("Bad RAR file.")
            self.reports["error"] = Report("Bad RAR file.")
        except rarfile.NotRarFile:
            log.error("Not a valid RAR file.")
            self.reports["error"] = Report("Not a valid RAR file.")

    def _test_passwords(self, rf, password_list):
        for password in password_list:
            try:
                rf.setpassword(password)
                # Try reading the first file to verify the password
                for f in rf.infolist():
                    if not f.is_dir():
                        rf.read(f.filename)
                        break
                self.reports["password"] = Report(password)
                self._extract_contents(rf)
                return True
            except (rarfile.BadRarPassword, rarfile.RarWrongPassword):
                continue
            except rarfile.RarCannotExec:
                log.error("unrar not found — install unrar to extract RAR files.")
                self.reports["error"] = Report(
                    "unrar not installed — cannot extract RAR contents",
                    severity=Severity.LOW,
                )
                return False
            except Exception:
                continue
        return False

    def _extract_contents(self, rf):
        for idx, file_info in enumerate(rf.infolist()):
            if file_info.is_dir():
                continue
            member_key = (file_info.filename, file_info.file_size)
            if member_key in self._extracted_members:
                continue
            try:
                file_data = rf.read(file_info.filename)
                self.childitems.append(
                    self.generate_struct(
                        filename=file_info.filename,
                        data=file_data,
                        index=idx,
                    )
                )
                self._extracted_members.add(member_key)
            except Exception as e:
                log.error(f"Could not extract {file_info.filename} from RAR: {e}")

    def _retry_with_password(self, password):
        try:
            file_like_object = io.BytesIO(self.struct.rawdata)
            rf = rarfile.RarFile(file_like_object)
            rf.setpassword(password)
            # Verify password by reading first file
            for f in rf.infolist():
                if not f.is_dir():
                    rf.read(f.filename)
                    break
            self.reports["password_discovered"] = Report(
                "RAR unlocked with discovered password",
                label="password_discovered",
                rank=1,
            )
            self._extract_contents(rf)
            rf.close()
            return True
        except (rarfile.BadRarPassword, rarfile.RarWrongPassword):
            return False
        except Exception:
            return False

    def _on_unlocked(self, _password, _source_struct):
        self.reports["decrypted"] = Report(
            "Encrypted RAR decrypted after password discovery",
            label="decrypted",
            rank=1,
        )
