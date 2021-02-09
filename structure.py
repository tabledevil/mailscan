from ctypes import Structure
from sys import flags

from pytz import NonExistentTimeError
from eml import Eml
import magic
import os
import hashlib
import logging
import inspect
import time
import textwrap
from icecream import ic
from pprint import pprint as pp

class AnalysisModuleException(Exception):
    pass




class Report():
    def __init__(self,text,short=None,label='',rank=0,verbosity=0):
        self.text = text
        self.short = self.text if short is None else short
        self.label = label
        self.rank = rank
        self.verbosity = verbosity
    
    def __str__(self) -> str:
        return self.text

class Analyzer():
    compatible_mime_types = []
    description = "Generic Analyzer Class"
    modules = {}

    def __init__(self,struct) -> None:
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
                logging.debug(f'Error during Module {module} : {e.msg}')
            except Exception as e:
                if debug:
                    raise

    def analysis(self):
        self.run_modules()

    @staticmethod
    def get_analyzer(mimetype):
        for analyser in Analyzer.__subclasses__():
            if mimetype in analyser.compatible_mime_types:
                return analyser
        return Analyzer

    def get_childitems(self) -> list():
        return self.childitems

    @property
    def summary(self):
        summary = ""
        for report in self.reports:
            #TODO filter by verbosity and sort by rank
            summary += f"{report} : {self.reports[report].short}\n"
        return summary

    @property
    def reports_available(self):
        return self.reports.keys()

    def __str__(self) -> str:
        return type(self).description

    def get_childitems(self) -> list():
        return self.childitems

class EmailAnalyzer(Analyzer):
    compatible_mime_types = ['message/rfc822']
    description = "Email analyser"

    def parse_mail(self):

        import eml
        self.eml=Eml(filename=self.struct.filename, data=self.struct.rawdata)
        self.info = f'{",".join(self.eml.subject)}'
        summary = ""
        for f in self.eml.froms:
            summary += f"From   : {f}\n"
        for t in self.eml.tos:
            summary += f"To     : {t}\n"
            summary += f"Date   : {self.eml.date}\n"
        for s in self.eml.subject:
            summary += f"Subject   : {s}\n"
        self.reports['summary'] = Report(f'{summary}')


    def extract_parts(self):
        for idx,part in enumerate([x for x in self.eml.flat_struct if x['data']]):
            ic(part['filename'])
            self.childitems.append(Structure(file=part['filename'],data=part['data'],mime_type=part['content_type'],level=self.struct.level+1,index=idx))



    def analysis(self):
        self.modules['emailparser'] = self.parse_mail 
        self.modules['extract_parts'] = self.extract_parts
        ic(self.childitems)
        self.run_modules()




class PlainTextAnalyzer(Analyzer):
    compatible_mime_types =['text/plain']
    description = 'Plain Textfile Analyser'
    LANGUAGE_DB = 'lid.176.ftz'
    LANGUAGE_DB_URL = 'https://dl.fbaipublicfiles.com/fasttext/supervised-models/lid.176.ftz'


    def detect_language_fasttext(self):
        import fasttext
        if not os.path.isfile(self.LANGUAGE_DB):
            import requests
            logging.debug('Language File not Found. Download Starting...')
            r = requests.get(self.LANGUAGE_DB_URL)
            with open(self.LANGUAGE_DB,'wb') as output_file:
                output_file.write(r.content)
        model = fasttext.load_model(self.LANGUAGE_DB)
        predictions,_ = model.predict(self.text.splitlines())
        predictions = [p[0] for p in predictions]
        return max(set(predictions), key=predictions.count).replace('__label__','')
       

    def detect_language_langdetect(self):
        from langdetect import detect
        return detect(self.text)

    def detect_lang(self):
        resp = ""
        try:
            resp = self.detect_language_fasttext()
        except:
            pass
        if resp == "":
            try:
                resp = self.detect_language_langdetect()
            except:
                pass
        return resp

    def __decode(self, string):
        if isinstance(string, str):
            return string
        if isinstance(string, bytes):
            encodings = ['utf-8-sig', 'utf-16', 'iso-8859-15']
            encodings = self.__guess_encoding(string) + encodings
            for encoding in encodings:
                try:
                    return string.decode(encoding,errors='ignore')
                except UnicodeDecodeError:
                    pass

    def __guess_encoding(self,string):
        try:
            import chardet
            detection = chardet.detect(string)
            if "encoding" in detection and detection['encoding'] is not None and len(detection["encoding"]) > 2:
                return [detection["encoding"]]
        except ImportError:
            logging.warning('Missing module chardet')
        return []

    def decode(self):
        self.text = self.__decode(self.struct.rawdata)


    def analysis(self):
        self.text = "Could not decode"
        self.lang = ""
        self.modules['encoding'] = self.decode
        self.modules['language'] = self.detect_lang
        super().analysis()
       
        # self.lang = self.detect_lang()
        self.info = f"language:{self.lang} {len(self.text)}"
        self.reports['summary'] = Report(self.text,short=textwrap.shorten(self.text,width=100))

class HTMLAnalyzer(Analyzer):
    compatible_mime_types =['text/html']
    description = 'HTML Analyser'



    def analysis(self):
        super().analysis()
        from bs4 import BeautifulSoup as bs
        self.soup = bs(self.struct.rawdata,features="lxml")
        self.text = self.soup.getText()
        self.info = len(self.soup.contents)

    def get_childitems(self) -> list():
        return [Structure(data=self.text.encode(),mime_type="text/plain",level=self.struct.level+1)]
        
class PDFAnalyzer(Analyzer):
    compatible_mime_types =['application/pdf']
    description = 'PDF Analyser'

    def get_text(self):
        try:
            self.page_count = self.pdfobj.numPages
            txt = ""
            for page in range(self.page_count):
                page_object = self.pdfobj.getPage(page)
                txt += page_object.extractText()
            self.text=txt
            self.reports['pagecount']=Report(f'{self.pdfobj.numPages}',label="Pages")
            info = self.pdfobj.getDocumentInfo()
            if info.title:
                self.reports['title']=Report(f'{info.title}',label="title")
            if info.subject:
                self.reports['subject']=Report(f'{info.subject}',label="subject")
            if info.creator:
                self.reports['creator']=Report(f'{info.creator}',label="creator")
            if info.author:
                self.reports['author']=Report(f'{info.author}',label="Author")
            if info.producer:
                self.reports['producer']=Report(f'{info.producer}',label="producer")
            self.childitems.append(Structure(data=self.text.encode(),mime_type="text/plain",level=self.struct.level+1))

        except:
            pass
            
    def getAttachments(self):
      catalog = self.pdfobj.trailer["/Root"]
      fileNames = catalog['/Names']['/EmbeddedFiles']['/Names']
      attachments = {}
      for f in fileNames:
          ic(f)
          if isinstance(f, str):
              name = f
              dataIndex = fileNames.index(f) + 1
              fDict = fileNames[dataIndex].getObject()
              fData = fDict['/EF']['/F'].getData()
              attachments[name] = fData
      self.embedded_files = attachments

    def analysis(self):
        import io,PyPDF2
        fileobj = io.BytesIO(self.struct.rawdata)
        self.pdfobj = PyPDF2.PdfFileReader(fileobj)
        self.text = ""
        self.childitems = []
        self.modules['pdf2text'] = self.get_text
        # self.modules['embeddedFiles'] = self.getAttachments
        super().analysis()


class ZipAnalyzer(Analyzer):
    compatible_mime_types = ['application/zip']
    description = "ZIP-File analyser"

    def analysis(self):
        super().analysis()
        import zipfile, io
        file_like_object = io.BytesIO(self.struct.rawdata)
        self.zipobj = zipfile.ZipFile(file_like_object)
        self.info = f'{len(self.zipobj.filelist)} compressed file(s)'
        filelist = [f'{f.filename} [{f.file_size}]' for f in self.zipobj.filelist]
        self.reports['summary'] = Report('\n'.join(filelist))
    
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
        # if key != '__analyzer' and self.__analyzer and key in self.__analyzer.reports_available:
        #     return self.__analyzer.get_report(key)
        raise AttributeError(key)
    def __setattr__(self, name, value): 
        self[name] = value


    def __init__(self, file=None, data=None, mime_type=None, level=0, index=0) -> None:
        self.analyzer = None
        if data is None:
            if file is not None and os.path.isfile(file):
                self.fullpath = os.path.abspath(file)
                self.__filename = os.path.split(self.fullpath)[1]
                logging.debug(f'Reading file {self.fullpath}')
                with open(self.fullpath,'rb') as f:
                    self.__rawdata = f.read()
            else:
                raise ValueError("No Data was supplied for struct")

        else:
            self.__rawdata = data
            self.__filename = file if file is not None else None
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
            if hasattr(self,algo):
                hashes[algo] = getattr(self,algo)
        return hashes


    def get_report(self):
        txt =  f'{self.index} >> {self.mime_type} {self.size}\n'
        txt += f'info     : {self.analyzer.info}\n'
        if self.has_filename:
            txt += f'filename : {self.filename}\n'
        txt += f'md5      : {self.md5}\n'
        # txt += f'sha1     : {self.sha1}\n'
        # txt += f'sha256   : {self.sha256}\n'
        txt += f'{self.analyzer.summary}\n'
        for child in self.get_children():
            txt += f'{child.get_report()}'
        return textwrap.indent(txt,prefix="    " * self.level)

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

    
    def get_children(self):
        if self.__children is None:
            self.__children = self.analyzer.get_childitems()
        return self.__children




cwd=os.getcwd()
logging.info(f'Working directory: {cwd}')
debug = True
s1=Structure(file="mail.eml")

print(s1.get_report())

s3=Structure(file="test.pdf")
print(s3.get_report())

# s2=Structure(file="test.zip")
# print(s2.get_report())

    