"""
VBA macro extraction and analysis.

Decompresses VBA module streams from vbaProject.bin (MS-OVBA 2.4.1),
extracts readable source code, and scans for suspicious patterns.

No external dependencies beyond olefile (for OLE container parsing).
"""

import io
import logging
import math
import re
import struct

log = logging.getLogger("matt")


# ------------------------------------------------------------------
# VBA Decompression (MS-OVBA 2.4.1)
# ------------------------------------------------------------------

def _decompress_stream(compressed: bytes) -> bytes:
    """Decompress a VBA compressed container (MS-OVBA 2.4.1).

    Args:
        compressed: Raw compressed stream bytes.

    Returns:
        Decompressed bytes.

    Raises:
        ValueError: If the signature byte is invalid.
    """
    if not compressed:
        return b""

    if compressed[0] != 0x01:
        raise ValueError(f"Invalid VBA compression signature: 0x{compressed[0]:02X}")

    output = bytearray()
    pos = 1  # Skip signature byte

    while pos < len(compressed):
        # Read chunk header (2 bytes, little-endian)
        if pos + 2 > len(compressed):
            break
        header = struct.unpack_from("<H", compressed, pos)[0]
        pos += 2

        chunk_size = (header & 0x0FFF) + 3
        chunk_flag = (header >> 15) & 1
        chunk_data_end = pos + chunk_size - 2  # -2 for header already consumed

        if chunk_flag == 0:
            # Uncompressed chunk: copy 4096 bytes as-is
            end = min(pos + 4096, len(compressed))
            output.extend(compressed[pos:end])
            pos = end
        else:
            # Compressed chunk
            chunk_start = len(output)

            while pos < chunk_data_end and pos < len(compressed):
                # Read flag byte
                if pos >= len(compressed):
                    break
                flag_byte = compressed[pos]
                pos += 1

                for bit_index in range(8):
                    if pos >= chunk_data_end or pos >= len(compressed):
                        break

                    if (flag_byte >> bit_index) & 1 == 0:
                        # Literal token: copy one byte
                        output.append(compressed[pos])
                        pos += 1
                    else:
                        # Copy token: back-reference
                        if pos + 2 > len(compressed):
                            break
                        copy_token = struct.unpack_from("<H", compressed, pos)[0]
                        pos += 2

                        # Calculate bit sizes based on current decompressed position
                        difference = len(output) - chunk_start
                        bit_count = max((difference - 1).bit_length(), 4) if difference > 1 else 4

                        length_mask = 0xFFFF >> bit_count
                        offset_mask = ~length_mask & 0xFFFF

                        length = (copy_token & length_mask) + 3
                        offset = ((copy_token & offset_mask) >> (16 - bit_count)) + 1

                        # Copy from history
                        src = len(output) - offset
                        if src < 0:
                            break
                        for i in range(length):
                            if src + i < len(output):
                                output.append(output[src + i])
                            else:
                                break

    return bytes(output)


# ------------------------------------------------------------------
# Dir stream parsing (MS-OVBA 2.3.4.2)
# ------------------------------------------------------------------

def _read_uint16(data, offset):
    return struct.unpack_from("<H", data, offset)[0], offset + 2


def _read_uint32(data, offset):
    return struct.unpack_from("<I", data, offset)[0], offset + 4


def _read_record(data, offset):
    """Read a dir record: 2-byte ID + 4-byte size + data."""
    if offset + 6 > len(data):
        return None, None, None, offset
    rec_id, offset = _read_uint16(data, offset)
    rec_size, offset = _read_uint32(data, offset)
    rec_data = data[offset:offset + rec_size]
    return rec_id, rec_size, rec_data, offset + rec_size


def _parse_dir_stream(dir_data):
    """Parse the decompressed dir stream to extract module info.

    Returns:
        list of dicts: [{name, stream_name, text_offset}, ...]
    """
    modules = []
    offset = 0
    codepage = 1252  # default

    # Skip header records until we find PROJECTMODULES (0x000F)
    while offset < len(dir_data):
        rec_id, rec_size, rec_data, offset = _read_record(dir_data, offset)
        if rec_id is None:
            break

        # PROJECTCODEPAGE
        if rec_id == 0x0003 and rec_size == 2:
            codepage = struct.unpack_from("<H", rec_data, 0)[0]

        # PROJECTMODULES
        if rec_id == 0x000F:
            module_count = struct.unpack_from("<H", rec_data, 0)[0]
            # Skip PROJECTCOOKIE record (ID=0x0013)
            rec_id2, _, _, offset = _read_record(dir_data, offset)
            break
    else:
        return modules

    # Parse MODULE records
    for _ in range(module_count):
        module = {"name": "", "stream_name": "", "text_offset": 0}

        while offset < len(dir_data):
            rec_id, rec_size, rec_data, offset = _read_record(dir_data, offset)
            if rec_id is None:
                break

            # MODULENAME
            if rec_id == 0x0019:
                try:
                    module["name"] = rec_data.decode(_get_codec(codepage), errors="replace")
                except Exception:
                    module["name"] = rec_data.decode("latin-1", errors="replace")

            # MODULESTREAMNAME
            elif rec_id == 0x001A:
                try:
                    module["stream_name"] = rec_data.decode(_get_codec(codepage), errors="replace")
                except Exception:
                    module["stream_name"] = rec_data.decode("latin-1", errors="replace")
                # Skip the Unicode version (0x0032)
                _, _, _, offset = _read_record(dir_data, offset)

            # MODULEOFFSET
            elif rec_id == 0x0031:
                if rec_size >= 4:
                    module["text_offset"] = struct.unpack_from("<I", rec_data, 0)[0]

            # MODULEDOCSTRING — skip unicode pair
            elif rec_id == 0x001C:
                _, _, _, offset = _read_record(dir_data, offset)

            # TERMINATOR
            elif rec_id == 0x002B:
                break

        if module["stream_name"]:
            modules.append(module)

    return modules


def _get_codec(codepage):
    """Convert Windows codepage number to Python codec name."""
    mapping = {
        437: "cp437", 850: "cp850", 1250: "cp1250", 1251: "cp1251",
        1252: "cp1252", 1253: "cp1253", 1254: "cp1254", 1255: "cp1255",
        1256: "cp1256", 1257: "cp1257", 1258: "cp1258",
        10000: "mac_roman", 65001: "utf-8", 932: "cp932", 936: "cp936",
        949: "cp949", 950: "cp950",
    }
    return mapping.get(codepage, "cp1252")


# ------------------------------------------------------------------
# Suspicious VBA pattern detection
# ------------------------------------------------------------------

# Auto-execution entry points
AUTO_EXEC_KEYWORDS = [
    "AutoExec", "AutoOpen", "Auto_Open", "AutoClose", "Auto_Close",
    "AutoNew", "AutoExit", "Document_Open", "DocumentOpen",
    "Document_Close", "DocumentBeforeClose", "Document_New",
    "NewDocument", "Workbook_Open", "Workbook_Activate",
    "Workbook_BeforeClose", "Worksheet_Change",
    "App_DocumentOpen", "App_NewDocument", "App_DocumentBeforeClose",
    "UserForm_Initialize", "UserForm_Activate",
]

# Suspicious API calls / keywords grouped by category
SUSPICIOUS_PATTERNS = {
    "Shell execution": [
        "Shell", "WScript.Shell", "ShellExecute", "ShellExecuteA",
        "PowerShell", "Invoke-Expression", "cmd.exe", "cmd /c",
        "WScript.Run", "MacScript", "AppleScript",
    ],
    "Process/thread creation": [
        "CreateProcess", "CreateThread", "VirtualAlloc", "VirtualAllocEx",
        "WriteProcessMemory", "RtlMoveMemory", "NtCreateThreadEx",
    ],
    "File system operations": [
        "FileCopy", "Kill", "CreateTextFile", "SaveToFile",
        "Open.*For Output", "Open.*For Binary", "Open.*For Append",
    ],
    "Download/network": [
        "URLDownloadToFile", "URLDownloadToFileA",
        "Msxml2.XMLHTTP", "Microsoft.XMLHTTP",
        "Net.WebClient", "DownloadFile", "DownloadString",
        "InternetOpenA", "InternetOpenUrlA", "HttpOpenRequestA",
        "WinHttpRequest", "ServerXMLHTTP",
    ],
    "Registry access": [
        "RegOpenKeyEx", "RegOpenKeyExA", "RegQueryValueEx",
        "RegRead", "RegWrite", "RegDelete",
    ],
    "Obfuscation indicators": [
        "Chr\\(", "ChrB\\(", "ChrW\\(", "StrReverse",
        "CallByName", "Xor",
    ],
    "Macro self-modification": [
        "VBProject", "VBComponents", "CodeModule",
        "AddFromString", "InsertLines", "DeleteLines",
    ],
    "Security bypass": [
        "AccessVBOM", "VBAWarnings", "ProtectedView",
        "DisableAttachementsInPV", "DisableInternetFilesInPV",
    ],
    "Scheduled tasks / persistence": [
        "Schedule.Service", "Win32_ScheduledJob",
        "CurrentVersion\\\\Run", "HKCU\\\\Software",
    ],
    "Sandbox / VM evasion": [
        "VIRTUAL", "VMWARE", "VBOX", "SbieDll",
        "GetVolumeInformation", "GetTickCount",
        "RecentFiles.Count",
    ],
}

# Dangerous file extensions that might appear in string literals
DANGEROUS_EXTENSIONS = re.compile(
    r'["\'][^"\']*\.(?:exe|dll|scr|pif|com|bat|cmd|vbs|vbe|js|jse|wsf|wsh|ps1|hta|cpl)\b',
    re.IGNORECASE,
)


def scan_vba_code(source_code):
    """Scan decompressed VBA source for suspicious patterns.

    Args:
        source_code: Decompressed VBA source as a string.

    Returns:
        list of (matched_text, category, severity) tuples.
    """
    findings = []
    if not source_code:
        return findings

    # Check auto-execution keywords
    for keyword in AUTO_EXEC_KEYWORDS:
        if re.search(r"(?i)\b" + re.escape(keyword) + r"\b", source_code):
            findings.append((keyword, "Auto-execution trigger", "HIGH"))

    # Check suspicious patterns
    for category, patterns in SUSPICIOUS_PATTERNS.items():
        for pattern in patterns:
            try:
                match = re.search(r"(?i)\b" + pattern + r"\b", source_code)
                if match:
                    findings.append((match.group(), category, "CRITICAL"))
            except re.error:
                # Some patterns include regex special chars intentionally
                if pattern.lower() in source_code.lower():
                    findings.append((pattern, category, "CRITICAL"))

    # Check for dangerous file extensions in strings
    for match in DANGEROUS_EXTENSIONS.finditer(source_code):
        findings.append((match.group(), "Dangerous file extension", "HIGH"))

    return findings


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def extract_vba_from_ole_data(ole_data):
    """Extract VBA macros from an OLE container (vbaProject.bin or full doc).

    Args:
        ole_data: Raw bytes of an OLE file containing VBA project.

    Returns:
        list of dicts: [{name, code, findings}, ...]
        Each 'findings' is the result of scan_vba_code().
        Returns empty list on failure.
    """
    try:
        import olefile
    except ImportError:
        log.debug("olefile not available for VBA extraction")
        return []

    try:
        ole = olefile.OleFileIO(io.BytesIO(ole_data))
    except Exception as e:
        log.debug(f"Cannot open OLE for VBA extraction: {e}")
        return []

    results = []
    try:
        # Find the VBA storage — could be at root or under Macros/
        vba_root = None
        for candidate in [["VBA"], ["Macros", "VBA"], ["_VBA_PROJECT_CUR", "VBA"]]:
            if ole.exists("/".join(candidate)):
                vba_root = candidate
                break

        if vba_root is None:
            # Try to find any "dir" stream
            for entry in ole.listdir(streams=True, storages=False):
                if entry[-1].lower() == "dir":
                    vba_root = entry[:-1]
                    break

        if vba_root is None:
            return results

        # Read and decompress the dir stream
        dir_path = vba_root + ["dir"]
        if not ole.exists("/".join(dir_path)):
            return results

        dir_compressed = ole.openstream(dir_path).read()
        try:
            dir_data = _decompress_stream(dir_compressed)
        except Exception as e:
            log.debug(f"Failed to decompress VBA dir stream: {e}")
            return results

        # Parse dir to get module info
        modules = _parse_dir_stream(dir_data)

        # Extract each module's source code
        for mod in modules:
            stream_path = vba_root + [mod["stream_name"]]
            if not ole.exists("/".join(stream_path)):
                # Try case-insensitive fallback
                found = False
                for entry in ole.listdir(streams=True, storages=False):
                    if len(entry) == len(stream_path) and \
                       all(a.lower() == b.lower() for a, b in zip(entry, stream_path)):
                        stream_path = entry
                        found = True
                        break
                if not found:
                    continue

            try:
                raw = ole.openstream(stream_path).read()
                code_data = raw[mod["text_offset"]:]
                if not code_data:
                    continue

                decompressed = _decompress_stream(code_data)
                # Strip trailing null bytes from padding
                decompressed = decompressed.rstrip(b"\x00")
                # Decode to string
                try:
                    source = decompressed.decode("utf-8", errors="replace")
                except Exception:
                    source = decompressed.decode("latin-1", errors="replace")

                source = source.strip()
                if not source:
                    continue

                findings = scan_vba_code(source)
                results.append({
                    "name": mod["name"],
                    "code": source,
                    "findings": findings,
                })
            except Exception as e:
                log.debug(f"Failed to extract VBA module {mod['name']}: {e}")

    finally:
        ole.close()

    return results
