import logging
import re

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

try:
    from Utils.vba_extractor import extract_vba_from_ole_data

    _VBA_AVAILABLE = True
except ImportError:
    _VBA_AVAILABLE = False


# Auto-execute trigger procedure names. Source: Microsoft VBA reference
# + oletools' olevba auto-exec patterns.
#
# olevba already flags these in its "Suspicious" category, but it
# folds them into prose strings. Surfacing the procedure names as a
# structured list in the report ``data`` field gives analysts a quick
# at-a-glance enumeration ("this macro fires on Document_Open AND
# Workbook_BeforeClose").
_AUTOLOAD_TRIGGER_NAMES = (
    # Word document events
    "Document_Open", "Document_Close", "Document_New",
    "Document_BeforeSave", "Document_BeforeClose",
    # AutoExec macros (legacy names — still triggered by Word)
    "AutoOpen", "AutoNew", "AutoClose", "AutoExec", "AutoExit",
    # Excel workbook events
    "Workbook_Open", "Workbook_BeforeClose", "Workbook_BeforeSave",
    "Workbook_AfterOpen", "Workbook_NewSheet", "Workbook_Activate",
    "Workbook_Deactivate",
    # Excel auto-exec macros (legacy)
    "Auto_Open", "Auto_Close",
    # Application-scope events
    "Application_Startup", "Application_NewWorkbook",
    "Application_WorkbookOpen", "Application_DocumentOpen",
    # PowerPoint
    "Presentation_Open", "Presentation_NewSlide",
    "App_PresentationOpen", "App_NewPresentation",
)

# Regex matches ``Sub|Function|Private Sub|Public Function`` followed by
# the trigger name and optional parens. Word treats matching procedures
# in *any* module as auto-exec; we don't try to filter by module class.
_AUTOLOAD_RE = re.compile(
    r"^\s*(?:Private\s+|Public\s+)?(?:Sub|Function)\s+("
    + "|".join(re.escape(n) for n in _AUTOLOAD_TRIGGER_NAMES)
    + r")\s*\(",
    re.IGNORECASE | re.MULTILINE,
)

# UserForm / control-event handlers like ``Image1_Click``, ``Label1_Change``.
# These fire when the user interacts with a control, but malicious
# documents put exec logic in a "_Click" handler on a control they
# trigger from another macro to defeat naive scanners.
_CONTROL_EVENT_RE = re.compile(
    r"^\s*(?:Private\s+|Public\s+)?Sub\s+([A-Za-z_]\w*)_"
    r"(Click|Change|KeyPress|MouseDown|MouseUp|GotFocus|LostFocus)\s*\(",
    re.IGNORECASE | re.MULTILINE,
)


def _enumerate_autoload_triggers(code: str) -> list[dict]:
    """Find every named-autoload procedure declared in *code*.
    Returns list of dicts: ``{name, kind, line, module}`` (module is
    set by the caller). Line numbers point at the declaration line
    of the trigger name, not the leading whitespace span."""
    found = []
    for m in _AUTOLOAD_RE.finditer(code):
        # group(1) = trigger name; m.start(1) is its position
        line = code[: m.start(1)].count("\n") + 1
        found.append({
            "name": m.group(1),
            "kind": "autoload",
            "line": line,
        })
    for m in _CONTROL_EVENT_RE.finditer(code):
        line = code[: m.start(1)].count("\n") + 1
        found.append({
            "name": f"{m.group(1)}_{m.group(2)}",
            "kind": "control_event",
            "line": line,
        })
    return found


class VBAProjectAnalyzer(Analyzer):
    """
    Analyzes vbaProject.bin files — extracts and decompiles VBA macros
    using oletools, reports suspicious patterns.
    """

    compatible_mime_types = ["application/vnd.ms-office.vbaProject"]
    description = "VBA Macro Project Analyzer"
    specificity = 25
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

        all_triggers: list[dict] = []
        for mod in modules:
            code = mod["code"]
            name = mod["name"]

            display_code = code[:2000] + "..." if len(code) > 2000 else code
            self.reports[f"vba_source_{name}"] = Report(
                display_code,
                short=f"VBA module: {name} ({len(code)} chars)",
                label=f"VBA:{name}",
            )

            # Per-module auto-exec / event-handler enumeration. Adds
            # structured metadata that analysts can scan without
            # having to read the macro source.
            triggers = _enumerate_autoload_triggers(code)
            for trig in triggers:
                trig["module"] = name
                all_triggers.append(trig)

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

        # Aggregate trigger report — fires only when at least one auto-
        # exec or control-event procedure was found. Severity is
        # CRITICAL when any "autoload" trigger is present (those run
        # automatically on document-open) and HIGH for control-event
        # handlers in isolation (need user interaction or programmatic
        # call from elsewhere in the macro).
        if all_triggers:
            has_autoload = any(t["kind"] == "autoload" for t in all_triggers)
            sev = Severity.CRITICAL if has_autoload else Severity.HIGH
            lines = [
                f"  - {t['module']}.{t['name']} "
                f"({t['kind']}, line {t['line']})"
                for t in all_triggers
            ]
            self.reports["vba_autoload_triggers"] = Report(
                "VBA auto-exec / event-handler procedures:\n"
                + "\n".join(lines),
                short=f"{len(all_triggers)} VBA trigger(s)",
                label="vba_autoload_triggers",
                severity=sev,
                verbosity=0,
                order=22,
                data={
                    "count": len(all_triggers),
                    "has_autoload": has_autoload,
                    "triggers": all_triggers,
                },
            )
