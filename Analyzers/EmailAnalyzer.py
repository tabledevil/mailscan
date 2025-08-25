import logging
from structure import Analyzer, Report
from eml import Eml


class EmailAnalyzer(Analyzer):
    compatible_mime_types = ['message/rfc822','application/octet-stream']
    description = "Email analyser"
    pip_dependencies = ['chardet', 'python-magic', 'python-dateutil', 'pytz']

    def parse_mail(self):
        try:
            self.eml = Eml(filename=self.struct.filename, data=self.struct.rawdata)
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
        except ImportError as e:
            logging.warning(f"Could not parse email due to missing dependency: {e}")
        except Exception as e:
            logging.error(f"Error parsing email: {e}")


    def extract_parts(self):
        if not hasattr(self, 'eml'):
            return
        for idx, part in enumerate([x for x in self.eml.flat_struct if x['data']]):
            self.childitems.append(self.generate_struct(filename=part['filename'], data=part['data'], mime_type=part['content_type'], index=idx))

    def analysis(self):
        self.modules['emailparser'] = self.parse_mail
        self.modules['extract_parts'] = self.extract_parts
        self.run_modules()
