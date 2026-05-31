"""Tests for pstforensic.catalog (PLAN §9.1/§9.2).

Known-answer vectors cite the [MS-OXPROPS] property id / [MS-OXPROPS] §1.3.2
property-set GUID they lock. Per PLAN §0.5 no byte-level constant is trusted
until pinned by a test vector.
"""
from __future__ import annotations

import json
from importlib import resources

import pytest

from pstforensic.catalog import namedprops, oxprops


# --- oxprops forward name lookups ([MS-OXPROPS] canonical property ids) -------
@pytest.mark.parametrize(
    "prop_id, name",
    [
        (0x0037, "PidTagSubject"),            # [MS-OXPROPS] 2.1023
        (0x0C1A, "PidTagSenderName"),         # [MS-OXPROPS]
        (0x0C1F, "PidTagSenderEmailAddress"),
        (0x0E04, "PidTagDisplayTo"),
        (0x0E03, "PidTagDisplayCc"),
        (0x0042, "PidTagSentRepresentingName"),
        (0x0E1D, "PidTagNormalizedSubject"),
        (0x001A, "PidTagMessageClass"),
        (0x0E07, "PidTagMessageFlags"),
        (0x0E08, "PidTagMessageSize"),
        (0x0039, "PidTagClientSubmitTime"),
        (0x0E06, "PidTagMessageDeliveryTime"),
        (0x3007, "PidTagCreationTime"),
        (0x3008, "PidTagLastModificationTime"),
        (0x1000, "PidTagBody"),
        (0x1009, "PidTagRtfCompressed"),
        (0x1013, "PidTagBodyHtml"),
        (0x007D, "PidTagTransportMessageHeaders"),
        (0x0071, "PidTagConversationIndex"),
        (0x0070, "PidTagConversationTopic"),
        (0x3704, "PidTagAttachFilename"),
        (0x3707, "PidTagAttachLongFilename"),
        (0x3701, "PidTagAttachDataObject"),
        (0x3705, "PidTagAttachMethod"),
        (0x0FF9, "PidTagRecordKey"),
        (0x0C15, "PidTagRecipientType"),
        (0x3001, "PidTagDisplayName"),
        (0x3003, "PidTagEmailAddress"),
        (0x3002, "PidTagAddressType"),
        (0x0FFF, "PidTagEntryId"),
        (0x35E0, "PidTagIpmSubTreeEntryId"),
        (0x67FF, "PidTagPstPassword"),
        (0x0017, "PidTagImportance"),
        (0x0036, "PidTagSensitivity"),
    ],
)
def test_name_for_known_ids(prop_id: int, name: str) -> None:
    assert oxprops.name_for(prop_id) == name


def test_name_for_unknown_returns_none() -> None:
    # 0x8042 is in the named-property range; not a canonical-catalog id.
    assert oxprops.name_for(0x8042) is None
    assert oxprops.name_for(0xABCD) is None


# --- oxprops types ([MS-OXPROPS] property type codes) ------------------------
def test_type_for_string_property() -> None:
    # PidTagSubject is PtypString (0x001F) / PtypString8 (0x001E).
    types = oxprops.type_for(0x0037)
    assert types == (0x001F, 0x001E)


def test_type_for_time_property() -> None:
    # PidTagClientSubmitTime is PtypTime (0x0040).
    assert oxprops.type_for(0x0039) == (0x0040,)


def test_type_for_binary_property() -> None:
    # PidTagRtfCompressed is PtypBinary (0x0102).
    assert oxprops.type_for(0x1009) == (0x0102,)


def test_type_for_unknown_returns_none() -> None:
    assert oxprops.type_for(0xABCD) is None


# --- reverse lookup ----------------------------------------------------------
def test_reverse_name_to_id() -> None:
    assert oxprops.id_for_name("PidTagSubject") == 0x0037
    assert oxprops.id_for_name("PidTagSenderEmailAddress") == 0x0C1F
    assert oxprops.id_for_name("PidTagDoesNotExist") is None


def test_definition_round_trip() -> None:
    pdef = oxprops.definition_for(0x0037)
    assert pdef is not None
    assert pdef.prop_id == 0x0037
    assert pdef.name == "PidTagSubject"
    assert pdef.set is None
    assert 0x001F in pdef.types


def test_format_unknown() -> None:
    assert oxprops.format_unknown(0x8042, 0x001F) == "0x8042:001F (undefined)"


# --- JSON ships as package data and loads via importlib.resources ------------
def test_json_loads_via_importlib_resources() -> None:
    raw = (
        resources.files("pstforensic.catalog")
        .joinpath("oxprops_data.json")
        .read_text(encoding="utf-8")
    )
    data = json.loads(raw)
    assert isinstance(data, dict)
    # Real entries (non-metadata) are well-formed.
    real = {k: v for k, v in data.items() if not k.startswith("_")}
    for key, entry in real.items():
        assert key.startswith("0x")
        assert "name" in entry and entry["name"].startswith("PidTag")
        assert isinstance(entry["types"], list) and entry["types"]
        assert "set" in entry


def test_coverage_count() -> None:
    # Axis-B breadth gate (PLAN §1.3): ship a broad analyst-relevant catalog.
    assert len(oxprops.PROPS) >= 60


# --- named-prop set GUID lookups ([MS-OXPROPS] §1.3.2) -----------------------
def test_well_known_set_guids_present() -> None:
    sets = namedprops.WELL_KNOWN_SETS
    assert sets["00020328-0000-0000-c000-000000000046"] == "PS_MAPI"
    assert sets["00020329-0000-0000-c000-000000000046"] == "PS_PUBLIC_STRINGS"
    assert sets["00020386-0000-0000-c000-000000000046"] == "PS_INTERNET_HEADERS"
    assert sets["00062002-0000-0000-c000-000000000046"] == "PSETID_Appointment"
    assert sets["00062003-0000-0000-c000-000000000046"] == "PSETID_Task"
    assert sets["00062008-0000-0000-c000-000000000046"] == "PSETID_Common"
    assert sets["00062004-0000-0000-c000-000000000046"] == "PSETID_Address"
    assert sets["6ed8da90-450b-101b-98da-00aa003f1305"] == "PSETID_Meeting"


def test_set_name_helper() -> None:
    assert namedprops.set_name(namedprops.PS_MAPI) == "PS_MAPI"
    assert namedprops.set_name("DEADBEEF-0000-0000-0000-000000000000") is None


def test_guid_bytes_round_trip() -> None:
    # MAPI mixed-endian: first three groups little-endian, last two big-endian.
    # PS_MAPI {00020328-0000-0000-C000-000000000046} on disk:
    #   28 03 02 00 | 00 00 | 00 00 | C0 00 | 00 00 00 00 00 46
    raw = bytes.fromhex("2803020000000000c000000000000046")
    assert namedprops.guid_bytes_to_str(raw) == namedprops.PS_MAPI
    assert namedprops.guid_str_to_bytes(namedprops.PS_MAPI) == raw


def test_set_name_from_raw_bytes() -> None:
    raw = bytes.fromhex("2803020000000000c000000000000046")
    assert namedprops.set_name(raw) == "PS_MAPI"


# --- well-known LID resolution ([MS-OXPROPS] PidLid* definitions) ------------
def test_lid_name_reminder_set() -> None:
    # PidLidReminderSet — LID 0x8503 in PSETID_Common ([MS-OXOMSG]).
    assert namedprops.lid_name(namedprops.PSETID_COMMON, 0x8503) == "PidLidReminderSet"


def test_lid_name_appointment() -> None:
    assert (
        namedprops.lid_name(namedprops.PSETID_APPOINTMENT, 0x820D)
        == "PidLidAppointmentStartWhole"
    )


def test_lid_name_unknown_returns_none() -> None:
    assert namedprops.lid_name(namedprops.PSETID_COMMON, 0xFFFF) is None
    # Right LID, wrong set => None.
    assert namedprops.lid_name(namedprops.PSETID_TASK, 0x8503) is None


def test_lid_name_accepts_raw_guid_bytes() -> None:
    common_raw = namedprops.guid_str_to_bytes(namedprops.PSETID_COMMON)
    assert namedprops.lid_name(common_raw, 0x8503) == "PidLidReminderSet"
