"""
OLE Package stream parser.

Extracts embedded files from OLE Package streams (\x01Ole native data)
and OLE 1.0 embedded objects.  These are commonly used to embed
executables, scripts, and other payloads inside Office documents.

Formats handled:
- OLE Package (OleNativeStream) — MS-OLEDS 2.3.6
- OLE 1.0 Embedded Objects — MS-OLEDS 2.2
"""

import logging
import re
import struct
from dataclasses import dataclass, field
from typing import Optional

log = logging.getLogger("matt")

# Dangerous file extensions that indicate an embedded payload is likely malicious
DANGEROUS_EXTENSIONS = frozenset({
    ".exe", ".dll", ".scr", ".pif", ".com", ".bat", ".cmd",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".ps1",
    ".hta", ".cpl", ".msi", ".jar", ".lnk", ".inf",
})


@dataclass
class PackageResult:
    """Result of parsing an OLE Package stream."""
    filename: str = ""
    source_path: str = ""
    temp_path: str = ""
    payload: bytes = b""
    is_dangerous: bool = False
    format_type: str = ""  # "package", "ole1_embedded", "ole1_linked"

    @property
    def extension(self):
        if "." in self.filename:
            return "." + self.filename.rsplit(".", 1)[-1].lower()
        return ""


def _read_zero_string(data, offset, max_len=4096):
    """Read a null-terminated ANSI string."""
    end = data.find(b"\x00", offset, offset + max_len)
    if end == -1:
        return "", offset + max_len
    try:
        s = data[offset:end].decode("latin-1", errors="replace")
    except Exception:
        s = ""
    return s, end + 1


def _read_length_prefixed_string(data, offset):
    """Read a 4-byte length-prefixed ANSI string (OLE 1.0 format)."""
    if offset + 4 > len(data):
        return "", offset
    length = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if length == 0 or offset + length > len(data):
        return "", offset
    # Length includes null terminator
    try:
        s = data[offset:offset + length - 1].decode("latin-1", errors="replace")
    except Exception:
        s = ""
    return s, offset + length


def parse_ole_native_stream(data):
    """Parse an OleNativeStream (Package object).

    The stream format (MS-OLEDS 2.3.6):
        4 bytes: NativeDataSize (total size)
        2 bytes: unknown (type?)
        string:  Filename (null-terminated)
        string:  SourcePath (null-terminated)
        4 bytes: unknown1
        4 bytes: unknown2
        string:  TempPath (null-terminated)
        4 bytes: ActualSize (payload length)
        bytes:   Payload data

    Args:
        data: Raw bytes of the \x01Ole or Package stream.

    Returns:
        PackageResult or None on failure.
    """
    if not data or len(data) < 12:
        return None

    try:
        offset = 0
        result = PackageResult(format_type="package")

        # NativeDataSize
        native_size = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Type specifier (2 bytes)
        if offset + 2 > len(data):
            return None
        type_spec = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        # Filename
        result.filename, offset = _read_zero_string(data, offset)

        # Source path
        result.source_path, offset = _read_zero_string(data, offset)

        # Two unknown uint32s (timestamps or flags)
        if offset + 8 > len(data):
            # We might already have what we need — try to extract payload
            # from remaining data
            return _try_raw_payload(data, result)

        offset += 8  # skip unknown1 + unknown2

        # Temp path
        result.temp_path, offset = _read_zero_string(data, offset)

        # Actual payload size
        if offset + 4 > len(data):
            return _try_raw_payload(data, result)
        actual_size = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # Payload
        if actual_size > 0 and offset + actual_size <= len(data):
            result.payload = data[offset:offset + actual_size]
        elif offset < len(data):
            # Best effort: take remaining data
            result.payload = data[offset:]

        # Check if filename extension is dangerous
        result.is_dangerous = result.extension in DANGEROUS_EXTENSIONS

        return result if (result.filename or result.payload) else None

    except Exception as e:
        log.debug(f"Failed to parse OLE native stream: {e}")
        return None


def parse_ole1_embedded(data):
    """Parse an OLE 1.0 embedded object.

    The OLE 1.0 format (MS-OLEDS 2.2):
        4 bytes: OleVersion
        4 bytes: FormatId (0x01=Linked, 0x02=Embedded)
        string:  ClassName (length-prefixed)
        string:  TopicName (length-prefixed)
        string:  ItemName (length-prefixed)
        If FormatId == 0x02:
            4 bytes: DataSize
            bytes:   EmbeddedData

    Args:
        data: Raw bytes of the OLE 1.0 object.

    Returns:
        PackageResult or None on failure.
    """
    if not data or len(data) < 16:
        return None

    try:
        offset = 0

        # OleVersion
        ole_version = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        # FormatId
        format_id = struct.unpack_from("<I", data, offset)[0]
        offset += 4

        result = PackageResult()

        if format_id == 0x02:
            result.format_type = "ole1_embedded"
        elif format_id == 0x01:
            result.format_type = "ole1_linked"
        else:
            return None

        # ClassName (length-prefixed)
        class_name, offset = _read_length_prefixed_string(data, offset)

        # TopicName (length-prefixed) — often the source filename
        topic_name, offset = _read_length_prefixed_string(data, offset)
        if topic_name:
            result.source_path = topic_name

        # ItemName (length-prefixed)
        item_name, offset = _read_length_prefixed_string(data, offset)

        # For embedded objects, extract the data
        if format_id == 0x02:
            if offset + 4 > len(data):
                return None
            data_size = struct.unpack_from("<I", data, offset)[0]
            offset += 4

            if data_size > 0 and offset + data_size <= len(data):
                result.payload = data[offset:offset + data_size]
            elif offset < len(data):
                result.payload = data[offset:]

        # Try to extract filename from class_name or topic_name
        if topic_name and "." in topic_name:
            result.filename = topic_name.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
        elif class_name:
            result.filename = class_name

        result.is_dangerous = result.extension in DANGEROUS_EXTENSIONS

        return result if (result.payload or result.filename) else None

    except Exception as e:
        log.debug(f"Failed to parse OLE 1.0 object: {e}")
        return None


def parse_embedded_object(data):
    """Try to parse data as an OLE Package or OLE 1.0 object.

    Tries Package format first (more common in modern docs),
    then falls back to OLE 1.0 format.

    Args:
        data: Raw bytes of the embedded object stream.

    Returns:
        PackageResult or None.
    """
    if not data or len(data) < 8:
        return None

    # Try OLE 1.0 format first — check FormatId at offset 4
    try:
        format_id = struct.unpack_from("<I", data, 4)[0]
        if format_id in (0x01, 0x02):
            result = parse_ole1_embedded(data)
            if result and result.payload:
                return result
    except Exception:
        pass

    # Try Package format
    result = parse_ole_native_stream(data)
    if result and (result.payload or result.filename):
        return result

    return None


def _try_raw_payload(data, result):
    """Last-resort: if header parsing failed partway, try to salvage."""
    # If we at least got a filename, return what we have
    if result.filename:
        result.is_dangerous = result.extension in DANGEROUS_EXTENSIONS
        return result
    return None
