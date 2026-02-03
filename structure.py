import hashlib
import logging
import os
import textwrap
import mimetypes
import sys
from reporting import ReportManager
from Config.config import flags
import importlib
import shutil
import subprocess
from Utils.filetype import detect_mime

class AnalysisModuleException(Exception):
    pass


class Report:
    def __init__(self, text, short=None, label='', rank=0, verbosity=0, content_type='text/plain', data=None):
        self.text = text
        self.short = self.text if short is None else short
        self.label = label
        self.rank = rank
        self.verbosity = verbosity
        self.content_type = content_type
        self.data = data

    def to_dict(self):
        return {
            'text': self.text,
            'short': self.short,
            'label': self.label,
            'rank': self.rank,
            'verbosity': self.verbosity,
            'content_type': self.content_type,
            'data': self.data,
        }

    def __str__(self) -> str:
        return self.text


class Analyzer(object):
    compatible_mime_types = []
    description = "Generic Analyzer Class"
    modules = {}
    pip_dependencies = []
    system_dependencies = []
    system_dependencies_check = {}

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
                logging.error(f'Error during Module {module} : {e}')
            except Exception as e:
                logging.error(f"Error during Module {module} : {e}")
                if flags.debug:
                    raise

    def analysis(self):
        self.run_modules()

    @classmethod
    def is_available(cls):
        """
        Check if all dependencies for this analyzer are met.
        """
        # Check for pip dependencies
        for package in cls.pip_dependencies:
            try:
                importlib.import_module(package)
            except ImportError:
                return False, f"Missing pip dependency: {package}"

        # Check for system dependencies (simple check)
        for command in cls.system_dependencies:
            if not shutil.which(command):
                return False, f"Missing system dependency: {command}"

        # Perform enhanced system tool checks
        for command, check_details in cls.system_dependencies_check.items():
            if not shutil.which(command):
                return False, f"Missing system dependency: {command}"

            try:
                args = [command] + check_details['args']
                result = subprocess.run(args, capture_output=True, text=True, check=False)

                if check_details['expected_output'] not in result.stdout and check_details['expected_output'] not in result.stderr:
                    return False, f"System dependency {command} is not working as expected."

            except (subprocess.SubprocessError, FileNotFoundError) as e:
                return False, f"Error checking system dependency {command}: {e}"

        return True, ""

    @staticmethod
    def get_analyzer(mimetype):
        for analyser in Analyzer.__subclasses__():
            if mimetype in analyser.compatible_mime_types:
                if hasattr(analyser, 'is_available'):
                    available, reason = analyser.is_available()
                    if not available:
                        logging.warning(f"Analyzer {analyser.__name__} is not available: {reason}")
                        continue
                return analyser
        return Analyzer

    def generate_struct(self, data, filename=None, index=0, mime_type=None):
        return Structure.create(data=data, filename=filename, level=self.struct.level + 1, index=index,mime_type=mime_type)

    @property
    def summary(self):
        reports = sorted(self.reports.values(), key=lambda r: r.rank)
        return reports

    @property
    def reports_available(self):
        return self.reports.keys()

    def __str__(self) -> str:
        return type(self).description

    def get_childitems(self) -> list():
        return self.childitems

from Analyzers import *

class Structure(dict):
    _cache = {}

    @classmethod
    def create(cls, filename=None, data=None, mime_type=None, level=0, index=0):
        # Determine the raw data to calculate the hash
        if data is None:
            if filename is not None and os.path.isfile(filename):
                with open(filename, 'rb') as f:
                    raw_data = f.read()
            else:
                raise ValueError("No Data was supplied for struct")
        else:
            raw_data = data

        # Calculate hash
        sha256_hash = hashlib.sha256(raw_data).hexdigest()

        # Check cache
        if sha256_hash in cls._cache:
            logging.info(f"Returning cached Structure object for hash {sha256_hash[:10]}...")
            # Here we could adjust level/index if we decide to, for now just return
            return cls._cache[sha256_hash]

        # If not in cache, create a new one and cache it
        new_struct = cls(filename=filename, data=raw_data, mime_type=mime_type, level=level, index=index)
        cls._cache[sha256_hash] = new_struct
        return new_struct

    def __getattr__(self, key):
        if key in self:
            return self[key]
        # This is a bit of magic to dynamically calculate hashes. If an attribute
        # is requested that is a valid hash algorithm, we calculate the hash
        # of the raw data and store it in the object's dictionary. This way,
        # hashes are only calculated once and only when they are needed.
        if key in hashlib.algorithms_available:
            hasher = hashlib.new(key)
            hasher.update(self.rawdata)
            if hasher.digest_size > 0:
                self[key] = hasher.hexdigest()
                return self[key]
        # if key != '__analyzer' and self.__analyzer and key in self.__analyzer.reports_available:
        #     return self.__analyzer.get_report(key)
        raise AttributeError(key)

    def __setattr__(self, name, value):
        self[name] = value

    def __init__(self, filename=None, data=None, mime_type=None, level=0, index=0) -> None:
        if flags.debug:
            logging.getLogger() .setLevel(logging.DEBUG)

        if level > flags.max_analysis_depth:
            logging.warning(f"Max analysis depth reached ({flags.max_analysis_depth}), stopping analysis.")
            self.analyzer = Analyzer(self) # Create a dummy analyzer
            return

        self.analyzer = None
        if data is None:
            if filename is not None and os.path.isfile(filename):
                if os.path.getsize(filename) > flags.max_file_size:
                    raise ValueError(f"File {filename} is too large.")
                self.fullpath = os.path.abspath(filename)
                self.__filename = os.path.split(self.fullpath)[1]
                logging.debug(f'Reading file {self.fullpath}')
                with open(self.fullpath, 'rb') as f:
                    self.__rawdata = f.read()
            else:
                raise ValueError("No Data was supplied for struct")

        else:
            if len(data) > flags.max_file_size:
                raise ValueError("Data is too large.")
            self.__rawdata = data
            self.__filename = filename if filename is not None else None
        self.level = level
        self.index = index
        self.parent = None
        self.mime_type = self.magic if mime_type is None else mime_type
        self.type_mismatch = self.mime_type == self.magic
        self.__children = None
        self.analyzer = Analyzer.get_analyzer(self.mime_type)(self)

    @property
    def realfile(self):
        if os.path.isfile(self.filename):
            return self.size == os.stat(self.filename).st_size
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
        return len(self.rawdata)

    @property
    def hashes(self):
        hashes = {}
        for algo in hashlib.algorithms_available:
            if hasattr(self, algo):
                hashes[algo] = getattr(self, algo)
        return hashes

    def get_report(self, report_format='text', verbosity=0):
        manager = ReportManager(self, verbosity=verbosity)
        return manager.render(format=report_format)

    def extract(self, basepath=None, filenames=False, recursive=False):
        if basepath is None:
            basepath = os.getcwd()
        if not os.path.isdir(basepath):
            logging.debug(f"Creating folder {basepath}")
            os.makedirs(basepath)
        filename = self.sanitized_filename if filenames else self.generated_filename
        outfile = os.path.join(basepath,filename)
        logging.debug(f"Writing {outfile}")
        try:
            with open(outfile,'wb') as outfile_obj:
                outfile_obj.write(self.rawdata)
        except OSError as e:
            logging.error(f"Error during extraction [{e}]")
        if recursive and self.has_children:
            base, ext = os.path.splitext(outfile)
            newbasepath = os.path.join(base, "children")
            for child in self.get_children():
                child.extract(basepath=newbasepath,filenames=filenames,recursive=recursive)
        

    @property
    def has_children(self):
        return len(self.get_children()) > 0

    @property
    def sanitized_filename(self):
        import re
        _RE_REPLACE_SPECIAL = re.compile(r'''[ <>|:!&*?/]''')
        _RE_COMBINE_UNDERSCORE = re.compile(r"(?a:_+)")

        return _RE_COMBINE_UNDERSCORE.sub('_',_RE_REPLACE_SPECIAL.sub('_', self.filename))


    @property
    def generated_filename(self):
        filename=f"{self.md5}{mimetypes.guess_extension(self.magic,strict=False)}"
        return filename


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
    logging.info(f'Working directory: {cwd}')

    s1 = Structure.create(filename="mail.eml")

    print(s1.get_report())

    s3 = Structure.create(filename="test.pdf")
    print(s3.get_report())

    # s2=Structure.create(file="test.zip")
    # print(s2.get_report())
