import logging
import io
import textwrap
import base64
from structure import Analyzer, Report, AnalysisModuleException
from pdf2image import convert_from_bytes

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None



class PDFAnalyzer(Analyzer):
    compatible_mime_types = ['application/pdf']
    description = 'PDF Analyser'
    pip_dependencies = ['PyPDF2', 'pdf2image']
    system_dependencies = ['pdftoppm']

    def parse_pdf(self):
        if not PyPDF2:
            raise AnalysisModuleException("PyPDF2 is not installed.")

        fileobj = io.BytesIO(self.struct.rawdata)
        try:
            self.pdfobj = PyPDF2.PdfReader(fileobj)
            self.page_count = len(self.pdfobj.pages)
            self.reports['pagecount'] = Report(f'{self.page_count}', label="Pages")

            info = self.pdfobj.metadata
            if info:
                if info.title:
                    self.reports['title'] = Report(f'{info.title}', label="title")
                if info.subject:
                    self.reports['subject'] = Report(f'{info.subject}', label="subject")
                if info.creator:
                    self.reports['creator'] = Report(f'{info.creator}', label="creator")
                if info.author:
                    self.reports['author'] = Report(f'{info.author}', label="Author")
                if info.producer:
                    self.reports['producer'] = Report(f'{info.producer}', label="producer")
        except PyPDF2.errors.PdfReadError as e:
            raise AnalysisModuleException(f"Error reading PDF file: {e}")


    def get_text(self):
        if hasattr(self,"pdfobj"):
            text = ""
            for page in range(self.page_count):
                try:
                    page_object = self.pdfobj.pages[page]
                    text += page_object.extract_text()
                except Exception as e:
                    logging.warning(f"Could not extract text from page {page}: {e}")
            if len(text) > 0:
                self.childitems.append(self.generate_struct(data=text.encode(), mime_type="text/plain"))
                self.reports['text'] = Report(text, short=textwrap.shorten(text, width=100))

    def getAttachments(self):
        if not hasattr(self, 'pdfobj'):
            return
        try:
            catalog = self.pdfobj.trailer["/Root"]
            if '/Names' not in catalog or '/EmbeddedFiles' not in catalog['/Names'] or '/Names' not in catalog['/Names']['/EmbeddedFiles']:
                return

            fileNames = catalog['/Names']['/EmbeddedFiles']['/Names']
            attachments = {}
            for i in range(0, len(fileNames), 2):
                name = fileNames[i]
                fDict = fileNames[i+1].get_object()
                if '/EF' in fDict and '/F' in fDict['/EF']:
                    fData = fDict['/EF']['/F'].get_data()
                    attachments[name] = fData
            self.embedded_files = attachments
            for name, data in attachments.items():
                self.childitems.append(self.generate_struct(data=data, filename=name))
        except Exception as e:
            logging.error(f"Error extracting embedded files from PDF: {e}")


    def generate_preview(self):
        try:
            images = convert_from_bytes(self.struct.rawdata, first_page=1, last_page=1, fmt='png')
            if images:
                image = images[0]
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                encoded_string = base64.b64encode(buffer.getvalue()).decode('ascii')
                self.reports['preview'] = Report(
                    text="First page preview",
                    label="Preview",
                    content_type='image/png',
                    data=encoded_string
                )
        except Exception as e:
            logging.warning(f"Could not generate PDF preview: {e}")

    def generate_preview(self):
        try:
            images = convert_from_bytes(self.struct.rawdata, first_page=1, last_page=1, fmt='png')
            if images:
                image = images[0]
                buffer = io.BytesIO()
                image.save(buffer, format="PNG")
                encoded_string = base64.b64encode(buffer.getvalue()).decode('ascii')
                self.reports['preview'] = Report(
                    text="First page preview",
                    label="Preview",
                    content_type='image/png',
                    data=encoded_string
                )
        except Exception as e:
            logging.warning(f"Could not generate PDF preview: {e}")

    def analysis(self):
        if not PyPDF2:
            logging.warning("PyPDF2 is not installed, cannot analyze PDF files.")
            return

        self.modules['parser'] = self.parse_pdf
        self.modules['pdf2text'] = self.get_text
        self.modules['embeddedFiles'] = self.getAttachments
        self.modules['preview'] = self.generate_preview

        super().analysis()
