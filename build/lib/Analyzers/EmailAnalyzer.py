import logging
import importlib
from structure import Analyzer, Report
# eml module is internal and now safe to import even if dependencies are missing
from eml import Eml


class EmailAnalyzer(Analyzer):
    compatible_mime_types = ['message/rfc822','application/octet-stream']
    description = "Email analyser"
    # These are dependencies used by the Eml class
    pip_dependencies = [
        ('chardet', 'chardet'),
        ('dateutil', 'python-dateutil'),
        ('pytz', 'pytz')
    ]

    def parse_mail(self):
        try:
            self.eml = Eml(filename=self.struct.filename, data=self.struct.rawdata)
            self.info = f'{",".join(self.eml.subject)}'
            summary = []
            for f in self.eml.froms:
                summary.append(f"From   : {f}\n")
            for t in self.eml.tos:
                summary.append(f"To     : {t}\n")
                summary.append(f"Date   : {self.eml.date}\n")
            for s in self.eml.subject:
                summary.append(f"Subject   : {s}\n")
            self.reports['summary'] = Report("".join(summary))
        except ImportError as e:
            logging.warning(f"Could not parse email due to missing dependency: {e}")
        except Exception as e:
            logging.error(f"Error parsing email: {e}")


    def extract_parts(self):
        if not hasattr(self, 'eml'):
            return
        for idx, part in enumerate(x for x in self.eml.flat_struct if x['data']):
            self.childitems.append(self.generate_struct(filename=part['filename'], data=part['data'], mime_type=part['content_type'], index=idx))

    def analysis(self):
        self.modules['emailparser'] = self.parse_mail
        self.modules['extract_parts'] = self.extract_parts
        self.run_modules()
