import hashlib
import logging
import os
import textwrap
import magic
import sys
from Config.config import flags
logging.getLogger()
logging.basicConfig(stream=sys.stderr, level=logging.INFO,format='[%(levelname)s]%(filename)s(%(lineno)d)/%(funcName)s:%(message)s')
class AnalysisModuleException(Exception):
    pass


class Report:
    def __init__(self, text, short=None, label='', rank=0, verbosity=0):
        self.text = text
        self.short = self.text if short is None else short
        self.label = label
        self.rank = rank
        self.verbosity = verbosity

    def __str__(self) -> str:
        return self.text


class Analyzer:
    compatible_mime_types = []
    description = "Generic Analyzer Class"
    modules = {}

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
                if flags.debug:
                    raise

    def analysis(self):
        self.run_modules()

    @staticmethod
    def get_analyzer(mimetype):
        for analyser in Analyzer.__subclasses__():
            if mimetype in analyser.compatible_mime_types:
                return analyser
        return Analyzer

    def get_childitems(self):
        return self.childitems

    def generate_struct(self, data, filename=None, index=0, mime_type=None):
        return Structure(data=data, filename=filename, level=self.struct.level + 1, index=index,mime_type=mime_type)

    @property
    def summary(self):
        summary = ""
        for report in self.reports:
            # TODO filter by verbosity and sort by rank
            summary += f"{report} : {self.reports[report].short}\n"
        return summary

    @property
    def reports_available(self):
        return self.reports.keys()

    def __str__(self) -> str:
        return type(self).description

    def get_childitems(self) -> list():
        return self.childitems



from Analyzers import *



class Structure(dict):
    def __getattr__(self, key):
        if key in self:
            return self[key]
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
        self.analyzer = None
        if data is None:
            if filename is not None and os.path.isfile(filename):
                self.fullpath = os.path.abspath(filename)
                self.__filename = os.path.split(self.fullpath)[1]
                logging.debug(f'Reading file {self.fullpath}')
                with open(self.fullpath, 'rb') as f:
                    self.__rawdata = f.read()
            else:
                raise ValueError("No Data was supplied for struct")

        else:
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
            return f"{self.md5[:8]}"

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

    def get_report(self):
        txt = f'{self.index} >> {self.mime_type} {self.size}\n'
        txt += f'info     : {self.analyzer.info}\n'
        if self.has_filename:
            txt += f'filename : {self.filename}\n'
        txt += f'md5      : {self.md5}\n'
        # txt += f'sha1     : {self.sha1}\n'
        # txt += f'sha256   : {self.sha256}\n'
        txt += f'{self.analyzer.summary}\n'
        for child in self.get_children():
            txt += f'{child.get_report()}'
        return textwrap.indent(txt, prefix="    " * self.level)

    def extract(self, basepath):
        pass

    @property
    def has_children(self):
        return len(self.get_children()) > 0

    @property
    def magic(self):
        if not hasattr(self, "__magic_mime"):
            self.__magic_mime = magic.from_buffer(self.rawdata, mime=True)
        return self.__magic_mime

    @property
    def magic_long(self):
        if not hasattr(self, "__magic_long"):
            self.__magic_long = magic.from_buffer(self.rawdata, mime=True)
        return self.__magic_long

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

    s1 = Structure(filename="mail.eml")

    print(s1.get_report())

    s3 = Structure(filename="test.pdf")
    print(s3.get_report())

    # s2=Structure(file="test.zip")
    # print(s2.get_report())
