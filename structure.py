from ctypes import Structure
from sys import flags
from eml import Eml
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

    def __init__(self,struct) -> None:
        self.struct = struct
        self.analysis_data = {}
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
        return []

    @property
    def info(self):
        return self.analysis_data['info']

    @property
    def summary(self):
        return self.analysis_data['summary']

    def get_report(self,report='info'):
        return self.analysis_data[report]

    @property
    def reports_available(self):
        return [report for report in self.analysis_data.keys()]

    def __str__(self) -> str:
        return type(self).description

class EmailAnalyzer(Analyzer):
    compatible_mime_types = ['message/rfc822']
    description = "Email analyser"

    def analysis(self):
        super().analysis()
        import eml
        self.eml=Eml(filename=self.struct.filename, data=self.struct.rawdata)
        self.analysis_data['info'] = f'{",".join(self.eml.subject)}'
        self.analysis_data['summary'] = f'{self.eml}'
    
    def get_childitems(self) -> list():
        childs = []
        for idx,part in enumerate([x for x in self.eml.flat_struct if x['data']]):
            childs.append(Structure(file=part['filename'],data=part['data'],mime_type=part['content_type'],level=self.struct.level+1,index=idx))
        return childs


    
class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"

    def analysis(self):
        super().analysis()
        import zipfile, io
        file_like_object = io.BytesIO(self.struct.rawdata)
        self.zipobj = zipfile.ZipFile(file_like_object)
        self.analysis_data['info'] = f'{len(self.zipobj.filelist)} compressed file(s)'
        filelist = [f'{f.filename} [{f.file_size}]' for f in self.zipobj.filelist]
        self.analysis_data['summary'] = '\n'.join(filelist)
    
    def get_childitems(self) -> list():
        return [Structure(file=name,data=self.zipobj.read(name),level=self.struct.level+1,index=index) for index, name in enumerate(self.zipobj.namelist())]


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
        if key is not '__analyzer' and self.__analyzer and key in self.__analyzer.reports_available:
            return self.__analyzer.get_report(key)
        raise AttributeError()
    def __setattr__(self, name, value): 
        self[name] = value

    def __init__(self, file=None, data=None, mime_type=None, level=0, index=0) -> None:
        self.__analyzer = None
        if data is None:
            if file is not None and os.path.isfile(file):
                self.fullpath = os.path.abspath(file)
                self.filename = os.path.split(self.fullpath)[1]
                logging.debug(f'Reading file {self.fullpath}')
                with open(self.fullpath,'rb') as f:
                    self.__rawdata = f.read()
            else:
                raise ValueError("No Data was supplied for struct")

        else:
            self.__rawdata = data
            self.filename = f"{self.md5[:8]}" if file is None else file
        self.level = level
        self.index = index
        self.parent = None
        self.mime_type = self.magic if mime_type is None else mime_type
        self.type_mismatch = self.mime_type == self.magic
        self.__children = None
        self.__analyzer = Analyzer.get_analyzer(self.magic)(self)

    @property
    def realfile(self):
        if os.path.isfile(self.filename):
            return self.size == os.stat(self.filename).st_size
        return False

    @property
    def rawdata(self):
        return self.__rawdata

    def __str__(self):
        # if self.realfile or self.filename:
        return f'{self.level}/{self.index}:{self.filename}[{self.mime_type}][{self.size}] <{self.info}>'
        # else:
        #     return f'{self.level}/{self.index}:{self.mime_type}[{self.md5}] <{self.info}>'

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
    def report(self):
        txt = f'{self}\n'
        for report in self.__analyzer.reports_available:
            txt += f'{self.__analyzer.get_report(report)}\n'
        return txt

    def extract(self,basepath):
        pass

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
        if self.__children is None:
            self.__children = self.__analyzer.get_childitems()
        return self.__children




cwd=os.getcwd()
logging.info(f'Working directory: {cwd}')
    
s1=Structure(file="mail.eml")
# s2=Structure(file="test.zip")
# with open('mail2.eml','rb') as f:
#     d=f.read()
# s3=Structure(data=d,file="mail.eml")

c=s1.children
# print(s1.report)
for x in c:
    print(x)



    