import magic
import os
import hashlib
import logging
import inspect
import time
from pprint import pprint as pp

class Analyzer():
    compatible_mime_types = []
    description = "Generic Analyzer Class"
    reports_available = ["summary"]
    def __init__(self,struct) -> None:
        self.struct = struct
        self.analysis_data = { }
        self.analysis()

    def analysis(self):
        self.analysis_data['summary'] = "Generic Analysis"
        self.analysis_data['info'] = self.description

    @staticmethod
    def get_analyzer(mimetype):
        for analyser in Analyzer.__subclasses__():
            if mimetype in analyser.compatible_mime_types:
                return analyser
        return Analyzer

    def get_childitems(self) -> list():
        pass

    @property
    def info(self):
        return self.analysis_data['info']

    def get_report(self,report='summary'):
        if report in self.reports_available:
            if not report in self.analysis_data:
                self.analysis()
            else:
                return self.analysis_data[report]

    def __str__(self) -> str:
        return type(self).description

class EmailAnalyzer(Analyzer):
    compatible_mime_types = ['message/rfc822']
    description = "Email analyser"



    
class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"

    def analysis(self):
        #super().analysis()
        import zipfile, io
        file_like_object = io.BytesIO(self.struct.rawdata)
        zipfile_ob = zipfile.ZipFile(file_like_object)
        self.analysis_data['info'] = f'{len(zipfile_ob.filelist)} compressed file(s)'
        self.analysis_data['summary'] = zipfile_ob.filelist


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
        raise AttributeError()
    def __setattr__(self, name, value): 
        self[name] = value

    def __init__(self, file=None, data=None, mime_type=None, path="", level=0, index=0) -> None:
        if file is not None and os.path.isfile(file):
            self.fullpath = os.path.abspath(file)
            self.filename = os.path.split(self.fullpath)[1]
            self.folder = os.path.split(self.fullpath)[0]
            self.abstractpath = self.fullpath
            self.realfile = True
            if data is None:
                self.read_rawdata()
            elif len(data) != os.stat(file).st_size:
                logging.error(f'Both data and filename was provided but length of file on disk an data differs : {len(data)} <> {os.stat(file).st_size}')
                self.rawdata = data
        else:
            self.rawdata = data
            self.realfile = False
            self.filename = f"[{self.md5[:8]}]"
        self.level = level
        self.index = index
        self.parent = None
        self.mime_type = self.magic if mime_type is None else mime_type
        self.type_mismatch = self.mime_type == self.magic
        self.__children = None
        self.analyzer = Analyzer.get_analyzer(self.magic)(self)

    def read_rawdata(self):
        logging.info(f'Reading file {self.fullpath}')
        try:
            with open(self.fullpath,'rb') as f:
                self.rawdata = f.read()
        except OSError as e:
            logging.error(f'Could not load Data from file "{e.filename}" [{e.strerror}]')


    def __str__(self):
        return f'{self.index}:{self.mime_type}[{self.size}] <{self.analyzer.info}>'

    @property
    def size(self):
        return len(self.rawdata)

    @property    
    def hashes(self):
        hashes = {}
        for algo in hashlib.algorithms_available:
            if hasattr(self,algo):
                hashes[algo] = getattr(self,algo)
        return hashes


    @property
    def has_children(self):
        return len(self.children) > 0


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

    @property
    def children(self):
        if self.__children is not None:
            return self.__children
        else:
            self.analyzer.get_childitems()




cwd=os.getcwd()
logging.info(f'Working directory: {cwd}')
    
s1=Structure(file="mail.eml")
s2=Structure(file="test.zip")
s3=Structure(file="test.exe")
# print(a.fullpath)
# print(a.filename)
# print(a.folder)

print(s1)
print(s2)
print(s3)
# print(Analyzer.inheritors())
# print(a.description)
# print(b.description)
# print(c.description)
# print(Analyzer.get_analyzer('message/rfc822').description)

    