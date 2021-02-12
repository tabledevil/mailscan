from structure import Analyzer, Report
import logging

class HTMLAnalyzer(Analyzer):
    compatible_mime_types = ['text/html']
    description = 'HTML Analyser'

    def analysis(self):
        super().analysis()
        from bs4 import BeautifulSoup as bs
        self.soup = bs(self.struct.rawdata, features="lxml")
        self.text = self.soup.getText()
        self.info = len(self.soup.contents)

    def get_childitems(self) -> list():
        return [self.generate_struct(data=self.text.encode(), mime_type="text/plain")]
