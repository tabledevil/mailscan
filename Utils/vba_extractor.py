"""
VBA macro extraction and analysis using oletools.

Wraps oletools.olevba to extract VBA source code from OLE containers
and analyze it for suspicious patterns.

Requires: oletools (pip install oletools)
"""

import logging

from oletools.olevba import VBA_Parser

log = logging.getLogger("matt")


# Map olevba analysis types to our severity levels
_SEVERITY_MAP = {
    "AutoExec": "HIGH",
    "Suspicious": "CRITICAL",
    "IOC": "HIGH",
    "Hex String": "MEDIUM",
    "Base64 String": "MEDIUM",
    "Dridex String": "CRITICAL",
    "VBA Stomping": "CRITICAL",
}


def scan_vba_code(source_code):
    """Scan VBA source for suspicious patterns using oletools.

    Args:
        source_code: VBA source as a string.

    Returns:
        list of (matched_text, category, severity) tuples.
    """
    if not source_code:
        return []

    findings = []
    try:
        vba = VBA_Parser("inline.bin", data=source_code.encode("utf-8", errors="replace"))
        try:
            for kw_type, keyword, description in vba.analyze_macros():
                severity = _SEVERITY_MAP.get(kw_type, "MEDIUM")
                findings.append((keyword, f"{kw_type}: {description}", severity))
        finally:
            vba.close()
    except Exception as e:
        log.debug(f"olevba scan_vba_code failed: {e}")

    return findings


def extract_vba_from_ole_data(ole_data):
    """Extract VBA macros from an OLE container (vbaProject.bin or full doc).

    Args:
        ole_data: Raw bytes of an OLE file containing VBA project.

    Returns:
        list of dicts: [{name, code, findings}, ...]
        Returns empty list on failure.
    """
    results = []

    try:
        vba = VBA_Parser("vbaProject.bin", data=ole_data)
    except Exception as e:
        log.debug(f"olevba cannot parse data: {e}")
        return results

    try:
        if not vba.detect_vba_macros():
            return results

        # Extract all macro source code
        for filename, stream_path, vba_filename, vba_code in vba.extract_macros():
            if not vba_code or not vba_code.strip():
                continue

            name = vba_filename or stream_path or filename
            code = vba_code.strip() if isinstance(vba_code, str) else vba_code.decode("utf-8", errors="replace").strip()

            results.append({
                "name": name,
                "code": code,
                "findings": [],  # populated below
            })

        # Run analysis across all macros
        analysis_results = list(vba.analyze_macros())

        # Attach findings to the first module (analysis is file-wide)
        if results and analysis_results:
            for kw_type, keyword, description in analysis_results:
                severity = _SEVERITY_MAP.get(kw_type, "MEDIUM")
                results[0]["findings"].append(
                    (keyword, f"{kw_type}: {description}", severity)
                )

    except Exception as e:
        log.debug(f"olevba extraction failed: {e}")
    finally:
        vba.close()

    return results
