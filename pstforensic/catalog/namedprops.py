"""Named-property set GUIDs and well-known LIDs (PLAN §9.2, §6.6).

Named properties (tags >= 0x8000) are resolved through a name-to-id map to a
``(GUID, LID|name)`` pair. This module ships:

* :data:`WELL_KNOWN_SETS` — the well-known property-set GUIDs (PS_MAPI,
  PS_PUBLIC_STRINGS, PS_INTERNET_HEADERS, and the appointment/task/common/
  address/meeting sets) keyed by their canonical RFC-4122 string form, mapping
  to a friendly set name ([MS-OXPROPS] 1.3.2 "Property Set Definitions").
* :func:`lid_name` — friendly labels for common ``PidLid*`` LIDs within those
  sets ([MS-OXPROPS] 2.x ``PidLid*`` definitions).

GUID handling note ([PLAN] §6.6 / Appendix A H17): in the PST/MSG name-to-id
map, ``wGuid == 1`` means PS_MAPI and ``wGuid == 2`` means PS_PUBLIC_STRINGS —
these are *hardcoded* GUIDs that are NOT present in the GUID stream; ``wGuid >= 3``
indexes ``GuidStream[wGuid - 3]``. The hardcoded GUIDs are exposed as
:data:`PS_MAPI` and :data:`PS_PUBLIC_STRINGS` for that resolution path.

GUIDs on disk are stored in MAPI mixed-endian layout (first three groups
little-endian, last two big-endian). :func:`guid_bytes_to_str` normalises raw
16-byte GUIDs to the canonical lowercase RFC-4122 string used as dict keys.
"""
from __future__ import annotations

import struct

__all__ = [
    "PS_MAPI",
    "PS_PUBLIC_STRINGS",
    "PS_INTERNET_HEADERS",
    "PSETID_APPOINTMENT",
    "PSETID_TASK",
    "PSETID_COMMON",
    "PSETID_ADDRESS",
    "PSETID_MEETING",
    "PSETID_NOTE",
    "PSETID_LOG",
    "WELL_KNOWN_SETS",
    "LID_NAMES",
    "guid_bytes_to_str",
    "guid_str_to_bytes",
    "set_name",
    "lid_name",
]

# --- Well-known property-set GUIDs (canonical RFC-4122 string form) ----------
# [MS-OXPROPS] §1.3.2 "Commonly Used Property Sets".
PS_MAPI = "00020328-0000-0000-c000-000000000046"
PS_PUBLIC_STRINGS = "00020329-0000-0000-c000-000000000046"
PS_INTERNET_HEADERS = "00020386-0000-0000-c000-000000000046"
PSETID_APPOINTMENT = "00062002-0000-0000-c000-000000000046"
PSETID_TASK = "00062003-0000-0000-c000-000000000046"
PSETID_ADDRESS = "00062004-0000-0000-c000-000000000046"
PSETID_COMMON = "00062008-0000-0000-c000-000000000046"
PSETID_NOTE = "0006200e-0000-0000-c000-000000000046"
PSETID_LOG = "0006200a-0000-0000-c000-000000000046"
# PSETID_Meeting ([MS-OXOCAL]) — note the distinct prefix.
PSETID_MEETING = "6ed8da90-450b-101b-98da-00aa003f1305"

#: GUID string -> friendly property-set name.
WELL_KNOWN_SETS: dict[str, str] = {
    PS_MAPI: "PS_MAPI",
    PS_PUBLIC_STRINGS: "PS_PUBLIC_STRINGS",
    PS_INTERNET_HEADERS: "PS_INTERNET_HEADERS",
    PSETID_APPOINTMENT: "PSETID_Appointment",
    PSETID_TASK: "PSETID_Task",
    PSETID_ADDRESS: "PSETID_Address",
    PSETID_COMMON: "PSETID_Common",
    PSETID_NOTE: "PSETID_Note",
    PSETID_LOG: "PSETID_Log",
    PSETID_MEETING: "PSETID_Meeting",
}


def guid_bytes_to_str(raw: bytes) -> str:
    """Convert a 16-byte MAPI mixed-endian GUID to a canonical RFC-4122 string.

    MAPI GUIDs are stored with the first three groups little-endian (4+2+2
    bytes) and the final two groups (2+6 bytes) byte-for-byte ([MS-DTYP] GUID;
    [PLAN] §9.4). The result is lowercase ``xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx``.

    Args:
        raw: Exactly 16 bytes of GUID data in on-disk layout.

    Returns:
        The canonical lowercase string form (the key used in
        :data:`WELL_KNOWN_SETS`).

    Raises:
        ValueError: If ``raw`` is not exactly 16 bytes.
    """
    if len(raw) != 16:
        raise ValueError(f"GUID must be 16 bytes, got {len(raw)}")
    d1, d2, d3 = struct.unpack_from("<IHH", raw, 0)
    d4 = raw[8:10]
    d5 = raw[10:16]
    return (
        f"{d1:08x}-{d2:04x}-{d3:04x}-"
        f"{d4.hex()}-{d5.hex()}"
    )


def guid_str_to_bytes(guid: str) -> bytes:
    """Convert a canonical RFC-4122 GUID string to 16-byte MAPI mixed-endian bytes.

    Inverse of :func:`guid_bytes_to_str`.

    Args:
        guid: A GUID string (hyphenated, case-insensitive).

    Returns:
        The 16-byte on-disk (mixed-endian) representation.
    """
    h = guid.replace("-", "")
    if len(h) != 32:
        raise ValueError(f"GUID string must be 32 hex digits, got {len(h)}")
    d1 = int(h[0:8], 16)
    d2 = int(h[8:12], 16)
    d3 = int(h[12:16], 16)
    tail = bytes.fromhex(h[16:32])
    return struct.pack("<IHH", d1, d2, d3) + tail


def _norm(guid: str | bytes) -> str:
    """Normalise a GUID (string or raw 16 bytes) to the canonical lowercase key."""
    if isinstance(guid, (bytes, bytearray)):
        return guid_bytes_to_str(bytes(guid))
    return guid.strip().lower()


def set_name(guid: str | bytes) -> str | None:
    """Return the friendly set name for a GUID (string or raw bytes), else ``None``.

    Args:
        guid: A GUID as a canonical string or as raw 16 on-disk bytes.

    Returns:
        The friendly set name (e.g. ``"PSETID_Common"``) or ``None`` if unknown.
    """
    return WELL_KNOWN_SETS.get(_norm(guid))


# --- Well-known LIDs by set ([MS-OXPROPS] PidLid* definitions) ---------------
# Keyed by (canonical GUID string, LID int) -> friendly PidLid* name.
LID_NAMES: dict[tuple[str, int], str] = {
    # PSETID_Common ([MS-OXCMSG], [MS-OXOFLAG], [MS-OXOMSG])
    (PSETID_COMMON, 0x8501): "PidLidReminderDelta",
    (PSETID_COMMON, 0x8502): "PidLidReminderTime",
    (PSETID_COMMON, 0x8503): "PidLidReminderSet",
    (PSETID_COMMON, 0x8506): "PidLidPrivate",
    (PSETID_COMMON, 0x8516): "PidLidCommonStart",
    (PSETID_COMMON, 0x8517): "PidLidCommonEnd",
    (PSETID_COMMON, 0x8518): "PidLidTaskMode",
    (PSETID_COMMON, 0x851C): "PidLidReminderSignalTime",
    (PSETID_COMMON, 0x8530): "PidLidFlagRequest",
    (PSETID_COMMON, 0x8552): "PidLidCurrentVersion",
    (PSETID_COMMON, 0x8554): "PidLidCurrentVersionName",
    (PSETID_COMMON, 0x8580): "PidLidInternetAccountName",
    (PSETID_COMMON, 0x8581): "PidLidInternetAccountStamp",
    (PSETID_COMMON, 0x85A0): "PidLidToDoOrdinalDate",
    (PSETID_COMMON, 0x85A1): "PidLidToDoSubOrdinal",
    (PSETID_COMMON, 0x85A4): "PidLidToDoTitle",
    # PSETID_Appointment ([MS-OXOCAL])
    (PSETID_APPOINTMENT, 0x8201): "PidLidAppointmentSequence",
    (PSETID_APPOINTMENT, 0x8205): "PidLidBusyStatus",
    (PSETID_APPOINTMENT, 0x8208): "PidLidLocation",
    (PSETID_APPOINTMENT, 0x820D): "PidLidAppointmentStartWhole",
    (PSETID_APPOINTMENT, 0x820E): "PidLidAppointmentEndWhole",
    (PSETID_APPOINTMENT, 0x8213): "PidLidAppointmentDuration",
    (PSETID_APPOINTMENT, 0x8215): "PidLidAppointmentSubType",
    (PSETID_APPOINTMENT, 0x8216): "PidLidAppointmentRecur",
    (PSETID_APPOINTMENT, 0x8217): "PidLidAppointmentStateFlags",
    (PSETID_APPOINTMENT, 0x8223): "PidLidRecurring",
    (PSETID_APPOINTMENT, 0x8224): "PidLidIntendedBusyStatus",
    (PSETID_APPOINTMENT, 0x8231): "PidLidRecurrenceType",
    (PSETID_APPOINTMENT, 0x8234): "PidLidTimeZoneDescription",
    (PSETID_APPOINTMENT, 0x8235): "PidLidClipStart",
    (PSETID_APPOINTMENT, 0x8236): "PidLidClipEnd",
    (PSETID_APPOINTMENT, 0x8580): "PidLidAppointmentCounterProposal",
    # PSETID_Meeting ([MS-OXOCAL])
    (PSETID_MEETING, 0x0002): "PidLidWhere",
    (PSETID_MEETING, 0x0003): "PidLidGlobalObjectId",
    (PSETID_MEETING, 0x0023): "PidLidCleanGlobalObjectId",
    (PSETID_MEETING, 0x0024): "PidLidMeetingType",
    (PSETID_MEETING, 0x0026): "PidLidMeetingType",
    # PSETID_Task ([MS-OXOTASK])
    (PSETID_TASK, 0x8101): "PidLidTaskStatus",
    (PSETID_TASK, 0x8102): "PidLidPercentComplete",
    (PSETID_TASK, 0x8103): "PidLidTeamTask",
    (PSETID_TASK, 0x8104): "PidLidTaskStartDate",
    (PSETID_TASK, 0x8105): "PidLidTaskDueDate",
    (PSETID_TASK, 0x810F): "PidLidTaskDateCompleted",
    (PSETID_TASK, 0x8116): "PidLidTaskComplete",
    (PSETID_TASK, 0x811C): "PidLidTaskComplete",
    (PSETID_TASK, 0x8124): "PidLidTaskOwner",
    # PSETID_Address ([MS-OXOCNTC])
    (PSETID_ADDRESS, 0x8005): "PidLidFileUnder",
    (PSETID_ADDRESS, 0x8045): "PidLidWorkAddressStreet",
    (PSETID_ADDRESS, 0x8046): "PidLidWorkAddressCity",
    (PSETID_ADDRESS, 0x8047): "PidLidWorkAddressState",
    (PSETID_ADDRESS, 0x8048): "PidLidWorkAddressPostalCode",
    (PSETID_ADDRESS, 0x8049): "PidLidWorkAddressCountry",
    (PSETID_ADDRESS, 0x8062): "PidLidInstantMessagingAddress",
    (PSETID_ADDRESS, 0x8080): "PidLidEmail1DisplayName",
    (PSETID_ADDRESS, 0x8082): "PidLidEmail1AddressType",
    (PSETID_ADDRESS, 0x8083): "PidLidEmail1EmailAddress",
    (PSETID_ADDRESS, 0x8084): "PidLidEmail1OriginalDisplayName",
}


def lid_name(guid: str | bytes, lid: int) -> str | None:
    """Return the friendly ``PidLid*`` name for a ``(set GUID, LID)`` pair.

    Args:
        guid: The property-set GUID (canonical string or raw 16 on-disk bytes).
        lid: The numeric LID (long id) within that set.

    Returns:
        The friendly ``PidLid*`` name, or ``None`` if the pairing is not in the
        well-known table.
    """
    return LID_NAMES.get((_norm(guid), lid))
