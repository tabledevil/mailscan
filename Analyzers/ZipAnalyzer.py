import io
import logging
import posixpath
import zipfile
from structure import Analyzer, Report, Severity
from Config.config import flags
from Utils.password_broker import PasswordBroker

log = logging.getLogger("matt")


class ZipAnalyzer(Analyzer):
    compatible_mime_types = ["application/zip", "application/x-zip-compressed"]
    description = "ZIP-File analyser"
    specificity = 10
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

                # Compression ratio — analyst signal (high = packed/bomb)
                if self.struct.size > 0 and total_uncompressed_size > 0:
                    ratio = total_uncompressed_size / self.struct.size
                    severity = (
                        Severity.MEDIUM if ratio > 100
                        else Severity.LOW if ratio > 20
                        else Severity.INFO
                    )
                    self.reports["compression_ratio"] = Report(
                        f"{ratio:.1f}:1 "
                        f"({total_uncompressed_size:,} / {self.struct.size:,} bytes)",
                        short=f"{ratio:.1f}:1",
                        label="compression_ratio",
                        severity=severity,
                        verbosity=0,
                    )
                if (
                    self.struct.size > 0
                    and total_uncompressed_size / self.struct.size
                    > flags.max_compression_ratio
                ):
                    log.warning("Zip bomb detected: compression ratio too high.")
                    self.reports["error"] = Report(
                        "Zip bomb detected: compression ratio too high."
                    )
                    return

                if total_uncompressed_size > flags.max_file_size:
                    log.warning(
                        "Zip bomb detected: total uncompressed size is too large."
                    )
                    self.reports["error"] = Report(
                        "Zip bomb detected: total uncompressed size is too large."
                    )
                    return

                # Path traversal checks (Zip Slip)
                traversal_paths = []
                absolute_paths = []
                for f in zip_file.infolist():
                    name = f.filename.replace("\\", "/")
                    if ".." in name.split("/"):
                        traversal_paths.append(f.filename)
                    elif name.startswith("/"):
                        absolute_paths.append(f.filename)
                if traversal_paths:
                    self.reports["path_traversal"] = Report(
                        f"ZIP path traversal (Zip Slip) detected: "
                        f"{', '.join(traversal_paths[:10])}",
                        severity=Severity.CRITICAL,
                    )
                    return
                if absolute_paths:
                    self.reports["absolute_path"] = Report(
                        f"ZIP contains absolute paths: "
                        f"{', '.join(absolute_paths[:10])}",
                        severity=Severity.HIGH,
                    )

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
                            log.warning(
                                "Could not find password for encrypted ZIP file."
                            )
                            return  # Stop for now, broker will retry later

                # If not encrypted, or if password was found, extract files
                self._extract_contents(zip_file)

        except zipfile.BadZipFile:
            log.error("Bad ZIP file.")
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
                if "compression method" in str(e).lower():
                    # AES-encrypted zips (pyzipper-only) — stdlib zipfile can't
                    # decrypt; record as a structured finding rather than spam.
                    self.reports["unsupported_compression"] = Report(
                        f"ZIP uses an encryption/compression method this build "
                        f"cannot probe (install py7zr/pyzipper for AES support): {e}",
                        severity=Severity.MEDIUM,
                    )
                    log.debug("ZIP compression method not supported: %s", e)
                    return False
                log.debug("Error testing password on ZIP file: %s", e)
                return False  # Stop on other errors
            except NotImplementedError as e:
                self.reports["unsupported_compression"] = Report(
                    f"ZIP uses an unsupported encryption method: {e}",
                    severity=Severity.MEDIUM,
                )
                log.debug("ZIP unsupported encryption: %s", e)
                return False
        return False

    def _extract_contents(self, zip_file):
        """Members become children under directory nodes that mirror the
        archive's folder hierarchy (``Structure.create_directory``).  Each
        file keeps its in-archive path as ``archive_path``; ``..``/absolute
        member names are normalized (zip-slip) and reported."""
        directories = getattr(self, "_directories", None)
        if directories is None:
            directories = self._directories = {}
        for idx, file_info in enumerate(zip_file.infolist()):
            member_path = self._normalized_member_path(file_info.filename)
            if not member_path:
                self.reports.setdefault("zip_path_traversal", Report(
                    f"Archive member with unsafe path skipped: {file_info.filename!r}",
                    short="unsafe member path", label="zip_path_traversal",
                    severity=Severity.MEDIUM, verbosity=0))
                continue
            if file_info.is_dir():
                self._directory_for_path(directories, member_path, idx)
                continue
            member_key = (file_info.filename, file_info.CRC, file_info.file_size)
            if member_key in self._extracted_members:
                continue
            try:
                file_data = zip_file.read(file_info.filename)
            except RuntimeError as e:
                log.error(f"Could not extract {file_info.filename} from zip: {e}")
                continue
            parent_path, filename = posixpath.split(member_path)
            siblings = self._children_for_path(directories, parent_path, idx)
            parent = directories.get(parent_path, self.struct) if parent_path else self.struct
            child = self.struct.__class__.create(
                filename=filename, data=file_data, index=idx,
                level=self._child_level(parent_path), parent=parent,
                metadata={"archive_filename": member_path},
            )
            child.archive_path = member_path
            siblings.append(child)
            self._extracted_members.add(member_key)

    def _children_for_path(self, directories, directory_path, index):
        if not directory_path:
            return self.childitems
        return self._directory_for_path(directories, directory_path, index).get_children()

    def _directory_for_path(self, directories, directory_path, index):
        directory_path = directory_path.rstrip("/")
        if directory_path in directories:
            return directories[directory_path]
        parent_path, dirname = posixpath.split(directory_path)
        siblings = self._children_for_path(directories, parent_path, index)
        directory = self.struct.__class__.create_directory(
            filename=dirname, index=index, level=self._child_level(parent_path),
            archive_path=directory_path,
            parent=directories[parent_path] if parent_path else self.struct,
        )
        directories[directory_path] = directory
        siblings.append(directory)
        return directory

    def _child_level(self, parent_path):
        if not parent_path:
            return self.struct.level + 1
        return self.struct.level + 2 + parent_path.count("/")

    @staticmethod
    def _normalized_member_path(filename):
        normalized = posixpath.normpath(filename.replace("\\", "/"))
        if normalized in {"", "."} or normalized == ".." or normalized.startswith("../"):
            return None
        return normalized.lstrip("/")

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
