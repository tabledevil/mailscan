from structure import Analyzer, Report, Severity


class VBAProjectAnalyzer(Analyzer):
    """
    Analyzes vbaProject.bin files. The mere presence of this file
    indicates the document contains VBA macros, which is a critical
    security finding.
    """

    # A1: removed 'application/octet-stream' — use can_handle() instead
    compatible_mime_types = ["application/vnd.ms-office.vbaProject"]
    description = "VBA Macro Project Analyzer"

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Match by filename — vbaProject.bin inside Office documents."""
        return bool(struct.filename and "vbaProject.bin" in struct.filename)

    def analysis(self):
        # Double-check the filename to be sure
        if self.struct.filename and "vbaProject.bin" not in self.struct.filename:
            return

        super().analysis()
        self.info = "Contains VBA Macros"
        self.reports["macros_found"] = Report(
            "Document contains VBA macros (vbaProject.bin found).",
            label="macros_found",
            severity=Severity.CRITICAL,
        )
