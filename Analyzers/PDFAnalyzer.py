from structure import Analyzer, AnalysisModuleException, Report
import logging
from pdf2image import convert_from_bytes
import base64
import io


class PDFAnalyzer(Analyzer):
    compatible_mime_types = ['application/pdf']
    description = 'PDF Analyser'

    def parse_pdf(self):
        import io, PyPDF2
        fileobj = io.BytesIO(self.struct.rawdata)
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


    def get_text(self):
        if hasattr(self,"pdfobj"):
            text = ""
            for page in range(self.page_count):
                page_object = self.pdfobj.pages[page]
                text += page_object.extract_text()
            if len(text) > 0:
                self.childitems.append(self.generate_struct(data=text.encode(), mime_type="text/plain"))
                import textwrap
                self.reports['text'] = Report(text, short=textwrap.shorten(text, width=100))

    def getAttachments(self):
        catalog = self.pdfobj.trailer["/Root"]
        fileNames = catalog['/Names']['/EmbeddedFiles']['/Names']
        attachments = {}
        for f in fileNames:
            if isinstance(f, str):
                name = f
                dataIndex = fileNames.index(f) + 1
                fDict = fileNames[dataIndex].getObject()
                fData = fDict['/EF']['/F'].getData()
                attachments[name] = fData
        self.embedded_files = attachments

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
        #self.text = ""
        #self.childitems = []
        self.modules['parser'] = self.parse_pdf
        self.modules['pdf2text'] = self.get_text
        self.modules['preview'] = self.generate_preview
        # self.modules['embeddedFiles'] = self.getAttachments
        super().analysis()

