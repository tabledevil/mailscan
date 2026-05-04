"""Office relationship (``_rels/*.rels``) analyzer.

Walks ``<Relationship>`` entries and flags external targets — the
delivery vector for several significant Office attack chains:

  * **CVE-2017-0199** — Word document with an ``oleObject`` rel whose
    ``Target`` is an external HTTP/HTTPS URL. Word fetches and renders
    the target on document-open, leading to arbitrary code execution
    via embedded HTA/RTF payloads.
  * **Remote-template injection** — ``attachedTemplate`` rel pointing
    at an external HTTP/HTTPS URL. Fetched on open; if the remote
    template carries macros, they execute.
  * **NTLM hash exfiltration** — any external rel whose Target is
    ``file://`` or a UNC path. Word/Excel transparently authenticate
    the SMB connection, leaking NetNTLMv2 to the attacker.
  * **Remote frames / altChunks** — external content rendered or
    imported into the document tree on open.

The previous implementation used legacy ``rank=`` keyword args, didn't
tag CVE-2017-0199 explicitly, and the external URL never propagated
into the root iocs_aggregate. Rewritten to use ``Severity`` consistently,
label findings precisely, and feed URLs into the IOC pipeline via the
standard report-text harvesting.
"""

import logging
import xml.etree.ElementTree as ET

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")


# Relationship type suffixes (after the last ``/``) we recognise.
# Source: https://learn.microsoft.com/en-us/dotnet/api/documentformat.openxml.packaging
_EXTERNAL_TYPE_RULES = {
    "oleObject":       (Severity.CRITICAL, "oleobject_remote",
                        "External OLE object — CVE-2017-0199 family"),
    "attachedTemplate": (Severity.CRITICAL, "remote_template",
                         "External attached template — remote-template "
                         "injection (executes macros on open)"),
    "frame":           (Severity.HIGH, "external_frame",
                        "External frame — fetches and renders remote content"),
    "altChunk":        (Severity.HIGH, "altchunk",
                        "External altChunk — imports remote content into "
                        "the document tree"),
    "subDocument":     (Severity.HIGH, "subdocument",
                        "External subDocument — included on document open"),
    "image":           (Severity.LOW, "external_image",
                        "External image — pixel-style tracking"),
    "hyperlink":       (Severity.INFO, "external_hyperlink",
                        "External hyperlink — user-clickable URL"),
}


def _classify(rel_type: str, target: str):
    """Map (rel_type, target) → (severity, key, description) or None
    when the relationship is not noteworthy."""
    target_lower = (target or "").lower()
    is_unc = (target_lower.startswith("file://")
              or target_lower.startswith("\\\\")
              or target_lower.startswith("//"))
    is_remote_proto = target_lower.startswith(("http://", "https://", "ftp://"))

    if not (is_remote_proto or is_unc):
        return None

    if is_unc:
        return (
            Severity.CRITICAL,
            "ntlm_leak",
            "External UNC/file:// target — NetNTLMv2 hash exfiltration "
            f"on open: {target}",
        )

    type_suffix = rel_type.split("/")[-1] if rel_type else ""
    matched = _EXTERNAL_TYPE_RULES.get(type_suffix)
    if matched:
        sev, key, desc = matched
        return sev, key, f"{desc}: {target}"

    # Unknown rel type with external target — flag MEDIUM as generic
    return (
        Severity.MEDIUM,
        "external_generic",
        f"External relationship (type={type_suffix or 'unknown'}): {target}",
    )


class OfficeRelationshipAnalyzer(Analyzer):
    """Analyze Office relationship (.rels) files for malicious external
    links — CVE-2017-0199, remote-template injection, NTLM hash leak,
    external frames/altChunks, etc."""

    compatible_mime_types = [
        "application/vnd.openxmlformats-package.relationships+xml",
        "application/xml",
    ]
    description = "Office Relationship File (.rels) Analyzer"
    specificity = 25

    def analysis(self):
        # Only run on .rels files, even if mime is generic application/xml
        if self.struct.filename and not self.struct.filename.endswith(".rels"):
            return

        super().analysis()

        ns = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}

        try:
            xml_content = self.struct.rawdata.decode("utf-8")
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            self.reports["parse_error"] = Report(
                f"XML Parse Error: {e}",
                label="parse_error",
                severity=Severity.LOW,
            )
            return
        except UnicodeDecodeError as e:
            self.reports["decode_error"] = Report(
                f"Unicode Decode Error: {e}",
                label="decode_error",
                severity=Severity.LOW,
            )
            return

        external_targets: list[dict] = []
        worst = Severity.INFO

        for idx, rel in enumerate(root.findall("r:Relationship", ns)):
            if rel.get("TargetMode") != "External":
                continue
            target = rel.get("Target", "")
            rel_type = rel.get("Type", "")
            classification = _classify(rel_type, target)
            if classification is None:
                continue
            severity, key, description = classification
            worst = min(worst, severity)
            label = f"external_rel_{key}"
            self.reports[f"{label}_{idx}"] = Report(
                description,
                short=f"{key}: {target[:80]}",
                label=label,
                severity=severity,
                verbosity=0,
                order=23,
                data={
                    "type": rel_type,
                    "target": target,
                    "severity": severity.name,
                    "kind": key,
                },
            )
            external_targets.append(
                {"type": rel_type, "target": target, "severity": severity.name,
                 "kind": key}
            )

        if external_targets:
            self.info = (
                f"{len(external_targets)} external relationship(s)"
            )
            self.reports["external_relationships"] = Report(
                "External targets:\n"
                + "\n".join(f"  - [{t['severity']}] {t['type']} → {t['target']}"
                            for t in external_targets),
                short=f"{len(external_targets)} external rel(s)",
                label="external_relationships",
                severity=worst,
                verbosity=0,
                order=22,
                data={"count": len(external_targets), "targets": external_targets},
            )
        else:
            self.info = "No external relationships found."
