import logging
import io
import textwrap
import base64
import importlib
import importlib.util
import shutil
from structure import Analyzer, Report, Severity, AnalysisModuleException

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None

try:
    from Utils import pdf_policy as _pdf_policy
    _PDF_POLICY_AVAILABLE = True
except ImportError:
    _PDF_POLICY_AVAILABLE = False



class PDFAnalyzer(Analyzer):
    compatible_mime_types = ['application/pdf']
    description = 'PDF Analyser'
    specificity = 20
    optional_pip_dependencies = ['PyPDF2', 'pdf2image']
    optional_system_dependencies = ['pdftoppm']
    extra = "pdf"

    def parse_pdf(self):
        if not PyPDF2:
            raise AnalysisModuleException("PyPDF2 is not installed.")

        fileobj = io.BytesIO(self.struct.rawdata)
        try:
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
        except PyPDF2.errors.PdfReadError as e:
            raise AnalysisModuleException(f"Error reading PDF file: {e}")


    def get_text(self):
        if hasattr(self,"pdfobj"):
            text = ""
            for page in range(self.page_count):
                try:
                    page_object = self.pdfobj.pages[page]
                    text += page_object.extract_text()
                except Exception as e:
                    logging.warning(f"Could not extract text from page {page}: {e}")
            if len(text) > 0:
                self.childitems.append(self.generate_struct(data=text.encode(), mime_type="text/plain"))
                self.reports['text'] = Report(text, short=textwrap.shorten(text, width=100))

    def getAttachments(self):
        if not hasattr(self, 'pdfobj'):
            return
        try:
            catalog = self.pdfobj.trailer["/Root"]
            if '/Names' not in catalog or '/EmbeddedFiles' not in catalog['/Names'] or '/Names' not in catalog['/Names']['/EmbeddedFiles']:
                return

            fileNames = catalog['/Names']['/EmbeddedFiles']['/Names']
            attachments = {}
            for i in range(0, len(fileNames), 2):
                name = fileNames[i]
                fDict = fileNames[i+1].get_object()
                if '/EF' in fDict and '/F' in fDict['/EF']:
                    fData = fDict['/EF']['/F'].get_data()
                    attachments[name] = fData
            self.embedded_files = attachments
            for name, data in attachments.items():
                self.childitems.append(self.generate_struct(data=data, filename=name))
        except Exception as e:
            logging.error(f"Error extracting embedded files from PDF: {e}")


    def generate_preview(self):
        if importlib.util.find_spec("pdf2image") is None:
            logging.warning("pdf2image is not installed, cannot generate PDF preview.")
            return
        if not shutil.which("pdftoppm"):
            logging.warning("poppler (pdftoppm) is not installed, cannot generate PDF preview.")
            return
        convert_from_bytes = importlib.import_module("pdf2image").convert_from_bytes
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

    def policy_check(self):
        """Run the pdfcop-parity policy scan and emit verdicts.

        Always runs even when PyPDF2 isn't available — the scan is byte-level
        and doesn't depend on the parser. Emits one report per profile that
        would have blocked, plus structured Findings reports."""
        if not _PDF_POLICY_AVAILABLE:
            return
        try:
            findings = _pdf_policy.scan(self.struct.rawdata)
        except Exception as e:
            logging.debug("pdf_policy scan failed: %s", e)
            return
        if not findings:
            return

        # Per-finding reports — graded by the worst right involved.
        worst = Severity.INFO
        for f in findings:
            sev = f.severity()
            worst = min(worst, sev)
            label = f"pdf_{f.kind}_{f.name}"
            self.reports[label] = Report(
                f"{f.kind}: {f.name}"
                + (f" (×{f.count})" if f.count > 1 else "")
                + (" [triggered at opening]" if f.triggered_at_opening else ""),
                short=f"{f.kind}:{f.name}",
                label=label.replace("@", "_at_"),
                severity=sev,
                verbosity=1,
                order=24,
                data={
                    "kind": f.kind, "name": f.name, "count": f.count,
                    "rights": list(f.rights),
                    "triggered_at_opening": f.triggered_at_opening,
                },
            )

        # Per-profile rollup so the analyst sees "this PDF would trigger
        # under standard / strong / paranoid" at a glance.
        profile_summary = {}
        for profile_name in ("standard", "strong", "paranoid"):
            verdicts = _pdf_policy.evaluate(findings, profile_name)
            profile_summary[profile_name] = [
                {"kind": v.finding.kind, "name": v.finding.name,
                 "blocked_by": list(v.blocked_by),
                 "severity": v.severity.name}
                for v in verdicts
            ]

        triggered_under = [name for name, v in profile_summary.items() if v]
        if triggered_under:
            std_count = len(profile_summary["standard"])
            strong_count = len(profile_summary["strong"])
            paranoid_count = len(profile_summary["paranoid"])
            text_lines = []
            for name, verdicts in profile_summary.items():
                if not verdicts:
                    continue
                text_lines.append(f"  [{name}] would block:")
                for v in verdicts:
                    text_lines.append(
                        f"    - {v['kind']}/{v['name']} "
                        f"({v['severity']}, blocked by {','.join(v['blocked_by'])})"
                    )
            # Severity for the overall finding = worst per-finding severity
            # we collected above (already in `worst`).
            self.reports["pdfcop_policy"] = Report(
                "PDF would trigger under: " + ", ".join(triggered_under)
                + f"\n  standard: {std_count}, strong: {strong_count}, "
                f"paranoid: {paranoid_count} blocking finding(s)\n"
                + "\n".join(text_lines),
                short="pdfcop: " + "/".join(triggered_under),
                label="pdfcop_policy",
                severity=worst,
                verbosity=0,
                order=23,
                data={"triggered_under": triggered_under,
                      "by_profile": profile_summary},
            )

    def analysis(self):
        if not PyPDF2:
            logging.warning("PyPDF2 is not installed, cannot analyze PDF files.")
            # Even without PyPDF2 we can still run the byte-level policy scan
            self.modules['policy'] = self.policy_check
            super().analysis()
            return

        self.modules['parser'] = self.parse_pdf
        self.modules['pdf2text'] = self.get_text
        self.modules['embeddedFiles'] = self.getAttachments
        self.modules['policy'] = self.policy_check
        self.modules['preview'] = self.generate_preview

        super().analysis()
