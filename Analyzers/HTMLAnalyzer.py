import logging
from .base import BaseAnalyzer, Report

try:
    from bs4 import BeautifulSoup as bs
except ImportError:
    bs = None

class HTMLAnalyzer(BaseAnalyzer):
    compatible_mime_types = ['text/html']
    description = 'HTML Analyser'
    pip_dependencies = ['beautifulsoup4', 'lxml']

    def analysis(self):
        super().analysis()
        if not bs:
            logging.warning("BeautifulSoup4 is not installed, cannot analyze HTML.")
            return
        self.soup = bs(self.struct.rawdata, features="lxml")
        self.text = self.soup.getText()
        self.info = len(self.soup.contents)

    def get_childitems(self) -> list():
        if hasattr(self, 'text'):
            return [self.generate_struct(data=self.text.encode(), mime_type="text/plain")]
        return []
