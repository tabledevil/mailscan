import importlib
import shutil
import logging
from Config.config import flags

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

class BaseAnalyzer(object):
    compatible_mime_types = []
    description = "Generic Analyzer Class"
    modules = {}
    pip_dependencies = []
    system_dependencies = []

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

    @staticmethod
    def get_analyzer(mimetype):
        for analyser in BaseAnalyzer.__subclasses__():
            if mimetype in analyser.compatible_mime_types:
                if hasattr(analyser, 'is_available'):
                    available, reason = analyser.is_available()
                    if not available:
                        logging.warning(f"Analyzer {analyser.__name__} is not available: {reason}")
                        continue
                return analyser
        return BaseAnalyzer

    def generate_struct(self, data, filename=None, index=0, mime_type=None):
        from structure import Structure
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

    @classmethod
    def is_available(cls):
        """
        Check if all dependencies for this analyzer are met.
        """
        for package in cls.pip_dependencies:
            try:
                importlib.import_module(package)
            except ImportError:
                return False, f"Missing pip dependency: {package}"

        for command in cls.system_dependencies:
            if not shutil.which(command):
                return False, f"Missing system dependency: {command}"

        return True, ""
