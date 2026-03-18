import logging

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

try:
    from Utils.vba_extractor import extract_vba_from_ole_data

    _VBA_AVAILABLE = True
except ImportError:
    _VBA_AVAILABLE = False


class VBAProjectAnalyzer(Analyzer):
    """
    Analyzes vbaProject.bin files — extracts and decompiles VBA macros
    using oletools, reports suspicious patterns.
    """

    compatible_mime_types = ["application/vnd.ms-office.vbaProject"]
    description = "VBA Macro Project Analyzer"
    pip_dependencies = ["oletools"]

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Match by filename — vbaProject.bin inside Office documents."""
        return bool(struct.filename and "vbaProject.bin" in struct.filename)

    def analysis(self):
        if self.struct.filename and "vbaProject.bin" not in self.struct.filename:
            return

        super().analysis()
        self.info = "Contains VBA Macros"
        self.reports["macros_found"] = Report(
            "Document contains VBA macros (vbaProject.bin found).",
            label="macros_found",
            severity=Severity.CRITICAL,
        )

        if not _VBA_AVAILABLE:
            return

        modules = extract_vba_from_ole_data(self.struct.rawdata)

        for mod in modules:
            code = mod["code"]
            name = mod["name"]

            display_code = code[:2000] + "..." if len(code) > 2000 else code
            self.reports[f"vba_source_{name}"] = Report(
                display_code,
                short=f"VBA module: {name} ({len(code)} chars)",
                label=f"VBA:{name}",
            )

            for matched, category, sev_str in mod["findings"]:
                sev = Severity.CRITICAL if sev_str == "CRITICAL" else Severity.HIGH
                key = f"vba_suspicious_{name}_{category}_{matched}"
                self.reports[key] = Report(
                    f"VBA module '{name}': {category} — {matched}",
                    severity=sev,
                )

            self.childitems.append(
                self.generate_struct(
                    data=code.encode("utf-8"),
                    filename=f"vba_source_{name}.vba",
                    mime_type="text/plain",
                    index=len(self.childitems),
                )
            )
