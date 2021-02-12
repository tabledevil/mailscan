from structure import Analyzer, AnalysisModuleException, Report
import logging


class PDFAnalyzer(Analyzer):
    compatible_mime_types = ['application/pdf']
    description = 'PDF Analyser'

    def parse_pdf(self):
        import io, PyPDF2
        fileobj = io.BytesIO(self.struct.rawdata)
        self.pdfobj = PyPDF2.PdfFileReader(fileobj)
        self.page_count = self.pdfobj.numPages
        self.reports['pagecount'] = Report(f'{self.pdfobj.numPages}', label="Pages")

        info = self.pdfobj.getDocumentInfo()
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
                page_object = self.pdfobj.getPage(page)
                text += page_object.extractText()
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

    def analysis(self):
        #self.text = ""
        #self.childitems = []
        self.modules['parser'] = self.parse_pdf
        self.modules['pdf2text'] = self.get_text
        # self.modules['embeddedFiles'] = self.getAttachments
        super().analysis()

