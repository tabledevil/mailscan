from structure import Analyzer, Report

class VBAProjectAnalyzer(Analyzer):
    """
    Analyzes vbaProject.bin files. The mere presence of this file
    indicates the document contains VBA macros, which is a critical
    security finding.
    """
    compatible_mime_types = ['application/vnd.ms-office.vbaProject', 'application/octet-stream']
    description = "VBA Macro Project Analyzer"

    def analysis(self):
        # Double-check the filename to be sure, in case of a generic MIME type
        if self.struct.filename and 'vbaProject.bin' not in self.struct.filename:
            return

        super().analysis()
        self.info = "Contains VBA Macros"
        self.reports['macros_found'] = Report(
            "CRITICAL: Document contains VBA macros (vbaProject.bin found).",
            rank=2
        )
