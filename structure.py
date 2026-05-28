import hashlib
import logging
import os
import re
import mimetypes
import weakref
from enum import IntEnum
from renderers import get_renderer
from Config.config import flags
import importlib
import importlib.util
import shutil
import subprocess
from Utils.filetype import detect_mime

log = logging.getLogger("matt")


class AnalysisModuleException(Exception):
    pass


class Severity(IntEnum):
    """Severity levels for analysis findings."""

    CRITICAL = 0  # confirmed malicious (VBA auto-exec+download, known-bad hash)
    HIGH = 1  # strong suspicion (encrypted attachment + password in body)
    MEDIUM = 2  # notable finding (DKIM expired, unusual file type)
    LOW = 3  # informational (encoding, language)
    INFO = 4  # metadata (hash, size, MIME type)


class Report:
    def __init__(
        self,
        text,
        short=None,
        label="",
        severity=Severity.INFO,
        verbosity=0,
        content_type="text/plain",
        data=None,
        replaces=None,
        # Legacy compat: accept 'rank' and map to severity
        rank=None,
    ):
        self.text = text
        self.short = self.text if short is None else short
        self.label = label
        # Support legacy 'rank' kwarg for backward compat with existing analyzers
        if rank is not None and severity == Severity.INFO:
            self.severity = Severity(min(rank, Severity.INFO))
        else:
            self.severity = severity
        self.verbosity = verbosity
        self.content_type = content_type
        self.data = data
        self.replaces = replaces

    @property
    def rank(self):
        """Legacy accessor — returns severity as int."""
        return int(self.severity)

    @property
    def is_finding(self):
        """True if this report represents a notable finding (MEDIUM or above)."""
        return self.severity <= Severity.MEDIUM

    def to_dict(self):
        return {
            "text": self.text,
            "short": self.short,
            "label": self.label,
            "severity": self.severity.name,
            "rank": self.rank,
            "verbosity": self.verbosity,
            "content_type": self.content_type,
            "data": self.data,
            "replaces": self.replaces,
        }

    def __str__(self) -> str:
        return str(self.text) if self.text is not None else ""

    def __repr__(self) -> str:
        return f"Report(label={self.label!r}, severity={self.severity.name}, text={str(self.text)[:60]!r})"


class Analyzer:
    compatible_mime_types = []
    description = "Generic Analyzer Class"
    modules = {}
    pip_dependencies = []
    optional_pip_dependencies = []
    system_dependencies = []
    system_dependencies_check = {}
    optional_system_dependencies = []
    optional_system_dependencies_check = {}
    required_alternatives = []
    extra = None

    def __init__(self, struct) -> None:
        self.struct = struct
        self.childitems = []
        self.reports = {}
        self.modules = {}
        self.info = ""
        self.analysis()

    def run_modules(self):
        for module in self.modules:
            try:
                self.modules[module]()
            except AnalysisModuleException as e:
                log.error(f"Error during Module {module} : {e}")
            except Exception as e:
                log.error(f"Error during Module {module} : {e}")
                if flags.debug:
                    raise

    def analysis(self):
        self.run_modules()

    # ------------------------------------------------------------------
    # A1: Content-based probe for ambiguous MIME types
    # ------------------------------------------------------------------
    @classmethod
    def can_handle(cls, struct) -> bool:
        """Override in subclasses to do content-based matching when the MIME
        type alone is ambiguous (e.g. application/octet-stream).  The base
        implementation always returns False."""
        return False

    @classmethod
    def is_available(cls):
        """Check if all dependencies for this analyzer are met."""
        for import_name, package in cls._normalize_pip_dependencies(
            cls.pip_dependencies
        ):
            if importlib.util.find_spec(import_name) is None:
                return False, f"Missing pip dependency: {package}"

        for group in cls.required_alternatives:
            group_met = False
            normalized_group = cls._normalize_pip_dependencies(group)
            for import_name, package in normalized_group:
                if importlib.util.find_spec(import_name) is not None:
                    group_met = True
                    break
            if not group_met:
                group_desc = " OR ".join([pkg for _, pkg in normalized_group])
                return False, f"Missing alternative dependency: {group_desc}"

        missing_required = cls._missing_system_dependencies(
            cls.system_dependencies,
            cls.system_dependencies_check,
        )
        if missing_required:
            return False, missing_required[0]

        return True, ""

    @classmethod
    def dependency_status(cls):
        missing_required = []
        missing_optional = []
        missing_alternatives = []

        for import_name, package in cls._normalize_pip_dependencies(
            cls.pip_dependencies
        ):
            if importlib.util.find_spec(import_name) is None:
                missing_required.append(package)
        for import_name, package in cls._normalize_pip_dependencies(
            cls.optional_pip_dependencies
        ):
            if importlib.util.find_spec(import_name) is None:
                missing_optional.append(package)

        for group in cls.required_alternatives:
            group_met = False
            normalized_group = cls._normalize_pip_dependencies(group)
            for import_name, package in normalized_group:
                if importlib.util.find_spec(import_name) is not None:
                    group_met = True
                    break
            if not group_met:
                group_desc = " OR ".join([pkg for _, pkg in normalized_group])
                missing_alternatives.append(f"({group_desc})")

        missing_required.extend(
            cls._missing_system_dependencies(
                cls.system_dependencies,
                cls.system_dependencies_check,
            )
        )
        missing_optional.extend(
            cls._missing_system_dependencies(
                cls.optional_system_dependencies,
                cls.optional_system_dependencies_check,
            )
        )

        return {
            "missing_required": missing_required,
            "missing_optional": missing_optional,
            "missing_alternatives": missing_alternatives,
        }

    @staticmethod
    def _normalize_pip_dependencies(dependencies):
        normalized = []
        for dependency in dependencies:
            if isinstance(dependency, (tuple, list)) and len(dependency) == 2:
                normalized.append((dependency[0], dependency[1]))
            else:
                normalized.append((str(dependency), str(dependency)))
        return normalized

    @staticmethod
    def _missing_system_dependencies(commands, checks):
        missing = []
        for command in commands:
            if not shutil.which(command):
                missing.append(f"Missing system dependency: {command}")
        for command, check_details in checks.items():
            if not shutil.which(command):
                missing.append(f"Missing system dependency: {command}")
                continue
            try:
                args = [command] + check_details["args"]
                result = subprocess.run(
                    args, capture_output=True, text=True, check=False
                )
                if (
                    check_details["expected_output"] not in result.stdout
                    and check_details["expected_output"] not in result.stderr
                ):
                    missing.append(
                        f"System dependency {command} is not working as expected."
                    )
            except (subprocess.SubprocessError, FileNotFoundError) as e:
                missing.append(f"Error checking system dependency {command}: {e}")
        return missing

    # ------------------------------------------------------------------
    # A1: Improved analyzer dispatch with can_handle() fallback
    # ------------------------------------------------------------------
    @staticmethod
    def get_analyzer(mimetype, struct=None):
        """Find the best analyzer for the given MIME type.

        1. Try exact MIME type match (first available wins).
        2. If MIME is ambiguous (application/octet-stream), probe each analyzer
           via ``can_handle(struct)`` for content-based matching.
        3. Fall back to the generic ``Analyzer`` base class.
        """
        ambiguous_types = {"application/octet-stream"}

        # Pass 1: exact MIME match
        exact_matches = [
            analyser
            for analyser in Analyzer.__subclasses__()
            if mimetype in analyser.compatible_mime_types
        ]

        if struct is not None and len(exact_matches) > 1:
            for analyser in exact_matches:
                try:
                    if analyser.can_handle(struct):
                        available, reason = analyser.is_available()
                        if not available:
                            log.warning(
                                f"Analyzer {analyser.__name__} matched content but is not available: {reason}"
                            )
                            continue
                        return analyser
                except Exception as e:
                    log.debug(f"can_handle() failed for {analyser.__name__}: {e}")

        for analyser in exact_matches:
            available, reason = analyser.is_available()
            if not available:
                log.warning(
                    f"Analyzer {analyser.__name__} is not available: {reason}"
                )
                continue
            return analyser

        # Pass 2: content-based probing for ambiguous types
        if mimetype in ambiguous_types and struct is not None:
            for analyser in Analyzer.__subclasses__():
                try:
                    if analyser.can_handle(struct):
                        available, reason = analyser.is_available()
                        if not available:
                            log.warning(
                                f"Analyzer {analyser.__name__} matched content but is not available: {reason}"
                            )
                            continue
                        return analyser
                except Exception as e:
                    log.debug(f"can_handle() failed for {analyser.__name__}: {e}")

        return Analyzer

    def generate_struct(self, data, filename=None, index=0, mime_type=None):
        return Structure.create(
            data=data,
            filename=filename,
            level=self.struct.level + 1,
            index=index,
            mime_type=mime_type,
        )

    @property
    def summary(self):
        reports = sorted(self.reports.values(), key=lambda r: r.rank)
        return reports

    @property
    def reports_available(self):
        return self.reports.keys()

    def __str__(self) -> str:
        return type(self).description

    def get_childitems(self) -> list:
        return self.childitems


class DirectoryAnalyzer(Analyzer):
    compatible_mime_types = ["inode/directory"]
    description = "Directory"

    def analysis(self):
        self.info = "directory"
        self.reports["summary"] = Report("Directory", label="directory", verbosity=1)


from Analyzers import *


class Structure(dict):
    _cache = {}

    # ------------------------------------------------------------------
    # A3: Cache management
    # ------------------------------------------------------------------
    @classmethod
    def clear_cache(cls):
        """Clear the analysis cache.  Call between top-level file analyses
        to free memory."""
        cls._cache.clear()

    @classmethod
    def cache_size(cls):
        return len(cls._cache)

    @staticmethod
    def _is_deferable_container(filename=None, mime_type=None):
        if filename:
            lower = str(filename).lower()
            if lower.endswith((".pst", ".mbox")):
                return True
        return mime_type in {
            "application/mbox",
            "application/vnd.ms-outlook-pst",
            "application/x-ms-pst",
            "application/x-pst",
        }

    # ------------------------------------------------------------------
    # File reading
    # ------------------------------------------------------------------
    @staticmethod
    def _read_data(filename=None, data=None):
        if data is not None:
            if len(data) > flags.max_file_size:
                raise ValueError("Data is too large.")
            return data
        if filename is not None and os.path.isfile(filename):
            if os.path.getsize(filename) > flags.max_file_size:
                raise ValueError(f"File {filename} is too large.")
            log.debug(f"Reading file {os.path.abspath(filename)}")
            with open(filename, "rb") as f:
                return f.read()
        raise ValueError("No Data was supplied for struct")

    # ------------------------------------------------------------------
    # Factory (with SHA-256 dedup cache)
    # ------------------------------------------------------------------
    @classmethod
    def create(cls, filename=None, data=None, mime_type=None, level=0, index=0):
        path_backed = False
        if data is None and filename is not None and os.path.isfile(filename):
            file_size = os.path.getsize(filename)
            if file_size > flags.max_file_size and cls._is_deferable_container(filename, mime_type):
                raw_data = b""
                path_backed = True
            else:
                raw_data = cls._read_data(filename, data)
        else:
            raw_data = cls._read_data(filename, data)

        # Calculate hash for dedup. Path-backed large containers are keyed by
        # file identity so different large files do not collide as empty bytes.
        if path_backed:
            stat = os.stat(filename)
            sha256_hash = hashlib.sha256(
                f"path:{os.path.abspath(filename)}:{stat.st_size}:{stat.st_mtime_ns}".encode("utf-8")
            ).hexdigest()
        else:
            sha256_hash = hashlib.sha256(raw_data).hexdigest()

        # Check cache
        if sha256_hash in cls._cache:
            cached_struct = cls._cache[sha256_hash]
            cached_struct._cache_occurrence_count += 1
            occurrence = cls._cached_occurrence(
                cached_struct,
                filename=filename,
                mime_type=mime_type,
                level=level,
                index=index,
                occurrence=cached_struct._cache_occurrence_count,
            )
            log.info(
                f"Returning cached Structure object for hash {sha256_hash[:10]}..."
            )
            return occurrence

        # A2: pass raw_data directly — __init__ will NOT re-read the file
        new_struct = cls(
            filename=filename,
            data=raw_data,
            mime_type=mime_type,
            level=level,
            index=index,
            path_backed=path_backed,
        )
        new_struct._cache_master = new_struct
        new_struct._cache_occurrence = 1
        new_struct._cache_occurrence_count = 1
        new_struct._content_sha256 = sha256_hash
        cls._cache[sha256_hash] = new_struct
        return new_struct

    @classmethod
    def create_directory(cls, filename, level=0, index=0, archive_path=None):
        obj = cls(
            filename=filename,
            data=b"",
            mime_type="inode/directory",
            level=level,
            index=index,
        )
        obj._Structure__children = []
        obj._cache_master = obj
        obj._cache_occurrence = 1
        obj._cache_occurrence_count = 1
        obj._content_sha256 = None
        obj.archive_path = archive_path
        return obj

    @classmethod
    def _cached_occurrence(
        cls, cached_struct, filename=None, mime_type=None, level=0, index=0, occurrence=1
    ):
        """Return a per-location wrapper for already analyzed bytes.

        The analyzer and child analysis are intentionally shared with the first
        occurrence, while presentation metadata belongs to the current archive
        member. This keeps deduplication as an analysis optimization without
        collapsing duplicate nodes in the rendered tree.
        """
        obj = cls.__new__(cls)
        dict.__init__(obj)

        obj._Structure__rawdata = cached_struct.rawdata
        if filename is not None and os.path.isfile(filename):
            obj.fullpath = os.path.abspath(filename)
            obj._Structure__filename = os.path.split(obj.fullpath)[1]
        else:
            obj._Structure__filename = filename if filename is not None else None

        obj.level = level
        obj.index = index
        obj.parent = None
        obj.mime_type = mime_type if mime_type is not None else cached_struct.mime_type
        obj.type_mismatch = getattr(cached_struct, "type_mismatch", False)
        obj._Structure__children = None
        obj.analyzer = cached_struct.analyzer
        obj._cache_master = cached_struct._cache_master
        obj._cache_occurrence = occurrence
        obj._content_sha256 = cached_struct._content_sha256
        return obj

    def __getattr__(self, key):
        if key in self:
            return self[key]
        # Lazy hash computation — any valid algorithm is computed on demand
        if key in hashlib.algorithms_available:
            if getattr(self, "path_backed", False):
                self[key] = None
                return self[key]
            hasher = hashlib.new(key)
            hasher.update(self.rawdata)
            if hasher.digest_size > 0:
                self[key] = hasher.hexdigest()
                return self[key]
        raise AttributeError(key)

    def __setattr__(self, name, value):
        self[name] = value

    # ------------------------------------------------------------------
    # A2: __init__ uses data directly — no second _read_data call
    # ------------------------------------------------------------------
    def __init__(
        self, filename=None, data=None, mime_type=None, level=0, index=0, path_backed=False
    ) -> None:
        if level > flags.max_analysis_depth:
            log.warning(
                f"Max analysis depth reached ({flags.max_analysis_depth}), stopping analysis."
            )
            self.analyzer = Analyzer(self)
            return

        self.analyzer = None

        # A2: Use data directly when provided (create() always passes it)
        if data is not None:
            self.__rawdata = data
        else:
            self.__rawdata = self._read_data(filename, data)

        if filename and os.path.isfile(filename):
            self.fullpath = os.path.abspath(filename)
            self.__filename = os.path.split(self.fullpath)[1]
        else:
            self.__filename = filename if filename is not None else None

        self.path_backed = path_backed
        self.level = level
        self.index = index
        self.parent = None

        # Determine MIME type
        if mime_type is not None:
            self.mime_type = mime_type
        elif path_backed and filename and str(filename).lower().endswith(".pst"):
            self.mime_type = "application/vnd.ms-outlook-pst"
        elif path_backed and filename and str(filename).lower().endswith(".mbox"):
            self.mime_type = "application/mbox"
        else:
            self.mime_type = self.magic

        # Only compute magic for type_mismatch if we got an explicit mime_type
        # and it's worth checking.  Avoids triggering expensive/crashy magic
        # detection when not needed.
        if mime_type is not None and not path_backed:
            try:
                self.type_mismatch = self.mime_type != self.magic
            except Exception:
                self.type_mismatch = False
        else:
            self.type_mismatch = False

        self.__children = None
        # A1: pass self to get_analyzer for content-based probing
        self.analyzer = Analyzer.get_analyzer(self.mime_type, struct=self)(self)

    @property
    def realfile(self):
        path = getattr(self, "fullpath", None) or self.__filename
        if path and os.path.isfile(path):
            return bool(getattr(self, "path_backed", False)) or self.size == os.stat(path).st_size
        return False

    @property
    def filename(self):
        if self.__filename is not None:
            return self.__filename
        else:
            return f"{self.md5[:8]}.{self.magic}"

    @property
    def has_filename(self):
        return self.__filename is not None

    @property
    def rawdata(self):
        return self.__rawdata

    def __str__(self):
        return self.analyzer.info

    @property
    def size(self):
        if getattr(self, "path_backed", False):
            path = getattr(self, "fullpath", None)
            if path and os.path.isfile(path):
                return os.path.getsize(path)
        return len(self.rawdata)

    @property
    def hashes(self):
        if getattr(self, "path_backed", False):
            return {}
        result = {}
        for algo in hashlib.algorithms_available:
            if hasattr(self, algo):
                result[algo] = getattr(self, algo)
        return result

    def get_report(self, report_format="rich", verbosity=0):
        renderer = get_renderer(report_format)
        return renderer.render(self, verbosity=verbosity)

    @property
    def duplicate_count(self):
        master = getattr(self, "_cache_master", self)
        return getattr(master, "_cache_occurrence_count", 1)

    @property
    def duplicate_occurrence(self):
        return getattr(self, "_cache_occurrence", 1)

    @property
    def is_duplicate_content(self):
        return not self.is_directory and self.duplicate_count > 1

    @property
    def is_directory(self):
        return self.mime_type == "inode/directory"

    def extract(self, basepath=None, filenames=False, recursive=False):
        if basepath is None:
            basepath = os.getcwd()
        if not os.path.isdir(basepath):
            log.debug(f"Creating folder {basepath}")
            os.makedirs(basepath)
        filename = self.sanitized_filename if filenames else self.generated_filename
        outfile = os.path.join(basepath, filename)
        if self.is_directory:
            log.debug(f"Creating directory {outfile}")
            os.makedirs(outfile, exist_ok=True)
        else:
            log.debug(f"Writing {outfile}")
            try:
                with open(outfile, "wb") as outfile_obj:
                    outfile_obj.write(self.rawdata)
            except OSError as e:
                log.error(f"Error during extraction [{e}]")
        if recursive and self.has_children:
            if self.is_directory:
                newbasepath = outfile
            else:
                base, ext = os.path.splitext(outfile)
                newbasepath = os.path.join(base, "children")
            for child in self.get_children():
                child.extract(
                    basepath=newbasepath, filenames=filenames, recursive=recursive
                )

    @property
    def has_children(self):
        return len(self.get_children()) > 0

    @property
    def sanitized_filename(self):
        _RE_REPLACE_SPECIAL = re.compile(r"""[ <>|:!&*?/]""")
        _RE_COMBINE_UNDERSCORE = re.compile(r"(?a:_+)")
        return _RE_COMBINE_UNDERSCORE.sub(
            "_", _RE_REPLACE_SPECIAL.sub("_", self.filename)
        )

    @property
    def generated_filename(self):
        if self.is_directory:
            return self.sanitized_filename
        ext = mimetypes.guess_extension(self.magic, strict=False) or ".bin"
        return f"{self.md5}{ext}"

    @property
    def magic(self):
        if not hasattr(self, "__magic_mime"):
            detection = detect_mime(self.rawdata, filename=self.__filename)
            self.__magic_detection = detection
            self.__magic_mime = detection.mime
            self.__magic_description = detection.description
        return self.__magic_mime

    @property
    def magic_detection(self):
        if not hasattr(self, "__magic_detection"):
            _ = self.magic
        return self.__magic_detection

    @property
    def magic_description(self):
        if not hasattr(self, "__magic_description"):
            _ = self.magic
        return self.__magic_description

    def get_children(self):
        if self.__children is None:
            self.__children = self.analyzer.get_childitems()
        return self.__children


if __name__ == "__main__":
    flags.debug = True
    if flags.debug:
        logging.basicConfig(level=logging.DEBUG)
    cwd = os.getcwd()
    log.info(f"Working directory: {cwd}")

    s1 = Structure.create(filename="mail.eml")
    print(s1.get_report())

    s3 = Structure.create(filename="test.pdf")
    print(s3.get_report())
