from structure import Analyzer, Report
import logging

from eml import Eml


class EmailAnalyzer(Analyzer):
    compatible_mime_types = ['message/rfc822']
    description = "Email analyser"

    def parse_mail(self):
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

    def extract_parts(self):
        for idx, part in enumerate([x for x in self.eml.flat_struct if x['data']]):
            self.childitems.append(self.generate_struct(filename=part['filename'], data=part['data'], mime_type=part['content_type'], index=idx))

    def analysis(self):
        self.modules['emailparser'] = self.parse_mail
        self.modules['extract_parts'] = self.extract_parts
        self.run_modules()
