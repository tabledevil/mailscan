import logging

from structure import Analyzer, Report, Severity
from Utils.mailbox_sources import iter_pst, looks_like_pst
from Utils.temp_manager import TempFileManager

try:
    import pypff
except ImportError:
    pypff = None

log = logging.getLogger("matt")


class PstAnalyzer(Analyzer):
    compatible_mime_types = [
        "application/vnd.ms-outlook",
        "application/vnd.ms-outlook-pst",
        "application/x-ms-pst",
        "application/x-pst",
    ]
    description = "PST mailbox analyzer"
    optional_pip_dependencies = [("pypff", "libpff-python")]
    extra = "pst"

    @classmethod
    def can_handle(cls, struct) -> bool:
        return looks_like_pst(getattr(struct, "filename", "") or "", getattr(struct, "rawdata", b""))

    def analysis(self):
        super().analysis()
        self.info = "PST mailbox"
        self.reports["summary"] = Report("PST mailbox", label="pst", verbosity=1)
        if getattr(self.struct, "path_backed", False):
            self.reports["path_backed"] = Report(
                "Large PST is analyzed directly from disk; full-file content hashing and generic byte scans are skipped.",
                short="Large PST streamed from disk",
                label="pst",
                verbosity=1,
            )

        if pypff is None:
            self.reports["pypff_missing"] = Report(
                "pypff is not installed; trying pffexport fallback if available.",
                short="pypff missing, using fallback",
                label="dependency",
                severity=Severity.LOW,
            )
            log.warning("pypff is not installed, trying pffexport fallback if available.")

        stats = {"messages": 0, "recovered": 0, "errors": 0, "pffexport": 0}
        if self.struct.realfile:
            self._process_pst_path(self.struct.fullpath, stats)
        else:
            with TempFileManager() as temp_manager:
                pst_path = temp_manager.create_temp_file(
                    self.struct.rawdata, suffix=".pst", prefix="matt_pst_"
                )
                self._process_pst_path(pst_path, stats)

        self.reports["messages"] = Report(
            f"Extracted {stats['messages']} PST message(s); recovered/orphan message(s): {stats['recovered']}; pffexport fallback message(s): {stats['pffexport']}.",
            short=f"{stats['messages']} PST message(s)",
            label="pst",
            verbosity=0,
        )
        if stats["errors"]:
            self.reports["partial_recovery"] = Report(
                f"PST parsing completed with {stats['errors']} recoverable error(s).",
                short="PST partially recovered",
                label="pst",
                severity=Severity.LOW,
            )

    def _process_pst_path(self, pst_path, stats):
        for record in iter_pst(pst_path):
            if record.error:
                stats["errors"] += 1
                self.reports[f"pst_error_{stats['errors']}"] = Report(
                    f"PST extraction error at {record.source}: {record.error}",
                    short="PST extraction error",
                    label="pst",
                    severity=Severity.MEDIUM,
                )
                log.warning("PST item error at %s: %s", record.source, record.error)
                continue
            stats["messages"] += 1
            if record.container == "pst-pffexport":
                stats["pffexport"] += 1
            if record.recovered:
                stats["recovered"] += 1
            self.childitems.append(
                self.generate_struct(
                    data=record.raw,
                    filename=self._message_filename(record),
                    index=record.index,
                    mime_type="message/rfc822",
                )
            )

    def _message_filename(self, record):
        prefix = "pst-recovered-message" if record.recovered else "pst-message"
        subject = record.source.rsplit(":", 1)[-1] if ":" in record.source else "message"
        safe = "".join(c if c.isalnum() or c in ".-_ " else "_" for c in subject).strip()
        safe = safe[:120].strip(" .") or "message"
        return f"{prefix}-{record.index}-{safe}.eml"
