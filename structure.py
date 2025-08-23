import hashlib
import logging
import os
import textwrap
import magic
import mimetypes
import sys
from Config.config import flags
import hashlib
import logging
import os
import textwrap
import magic
import mimetypes
import sys
from Analyzers.base import BaseAnalyzer, Report, AnalysisModuleException
logging.getLogger()
logging.basicConfig(stream=sys.stderr, level=logging.INFO,format='[%(levelname)s]%(filename)s(%(lineno)d)/%(funcName)s:%(message)s')
from Analyzers import *



class Structure(dict):
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
        self.analyzer = BaseAnalyzer.get_analyzer(self.mime_type)(self)

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
            self.__magic_mime = magic.from_buffer(self.rawdata, mime=True)
        return self.__magic_mime

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
