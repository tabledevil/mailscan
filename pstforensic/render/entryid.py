"""EntryID parsing ([MS-OXCDATA] §2.2.4; PLAN §9.4, Appendix A H18).

An EntryID is ``abFlags`` (4 bytes) + ``ProviderUID`` / MAPIUID (16 bytes) +
provider-specific data. The provider is identified primarily by the MAPIUID and
the provider-data layout. We parse the forensically useful kinds:

  * one-off recipient  (abFlags[0]==0x01, MAPIUID 81 2B 1F …) -> display /
    address-type / e-mail (this is where SMTP addresses come from);
  * address-book       (MAPIUID DCA740C8 … ) -> X500 DN (/O=.../OU=...);
  * store              -> provider UID + nothing addressable;
  * folder / message   -> store-UID + 2-byte folder type + 1 or 2 GIDs (NID-ish);
    these map provider-UID + NID and do **NOT** contain SMTP (Appendix A H18).

Pure, no I/O. Truncated input degrades gracefully (parse what is present).
"""
from __future__ import annotations

from typing import Any

from .guid import guid

# Well-known provider MAPIUIDs ([MS-OXCDATA] §2.2.4.x), stored mixed-endian like
# any GUID. Compared as raw 16-byte sequences for robustness.
_UID_ONE_OFF = bytes.fromhex("812b1fa4bea310199d6e00dd010f5402")
_UID_ADDRBOOK = bytes.fromhex("dca740c8c042101ab4b908002b2fe182")

# One-off abFlags / flags bits ([MS-OXCDATA] §2.2.4.5).
_ONEOFF_FLAG_UNICODE = 0x8000  # MAE_UNICODE in the version/flags word


def entryid(b: bytes) -> dict[str, Any]:
    """Parse an EntryID blob into a structured, human-readable dict.

    :param b: the raw EntryID bytes (``PidTagEntryId`` / ``PidTagStoreEntryId`` /
        recipient ``PidTagEntryId`` etc.).
    :returns: a dict always containing ``type``, ``raw_hex`` and (when present)
        ``mapiuid``; type-specific keys: one-off -> ``display``/``addrtype``/
        ``email``; address-book -> ``x500``/``dn``; store -> ``provider_uid``;
        folder/message -> ``store_uid``/``folder_type``/``global_counters``.
        Note (Appendix A H18): only one-off and address-book EntryIDs yield an
        address; store/folder/message EntryIDs do not contain SMTP.
    """
    out: dict[str, Any] = {"type": "unknown", "raw_hex": _hex(b)}
    if not isinstance(b, (bytes, bytearray)):
        out["type"] = "invalid"
        return out
    b = bytes(b)
    if len(b) < 4:
        out["type"] = "truncated"
        return out

    ab_flags = b[0:4]
    out["abflags"] = _hex(ab_flags)
    if len(b) < 20:
        out["type"] = "truncated"
        return out

    uid = b[4:20]
    out["mapiuid"] = guid(uid)
    provider = b[20:]

    # One-off recipient: abFlags[0] == 0x01 OR the one-off provider UID.
    if ab_flags[0] == 0x01 or uid == _UID_ONE_OFF:
        out["type"] = "one-off"
        _parse_oneoff(provider, out)
        return out

    if uid == _UID_ADDRBOOK:
        out["type"] = "address-book"
        _parse_addrbook(provider, out)
        return out

    # Store / folder / message EntryIDs: provider data begins with the store's
    # own MAPIUID, then a 2-byte object-type, then 1 (folder) or 2 (message)
    # 22-byte / 24-byte GIDs. We classify by remaining length (H18 note: no SMTP).
    out["type"] = "store-or-object"
    if len(provider) >= 16:
        out["store_uid"] = guid(provider[0:16])
    rest = provider[16:]
    if len(rest) >= 2:
        ftype = int.from_bytes(rest[0:2], "little")
        out["folder_type"] = ftype
        gids = rest[2:]
        # A GID is a 16-byte database GUID + 6-byte global counter (22B).
        counters = []
        for i in range(0, len(gids) - 21, 22):
            block = gids[i:i + 22]
            counters.append(
                {
                    "db_guid": guid(block[0:16]),
                    "global_counter": int.from_bytes(block[16:22], "little"),
                }
            )
        if counters:
            out["global_counters"] = counters
            out["type"] = "message" if len(counters) >= 2 else "folder"
        else:
            out["type"] = "store"
    else:
        out["type"] = "store"
    return out


def _parse_oneoff(provider: bytes, out: dict[str, Any]) -> None:
    """Parse a one-off EntryID's provider data ([MS-OXCDATA] §2.2.4.5).

    Layout: ``Version`` (u16) + ``Flags`` (u16, bit 0x8000 = Unicode strings)
    then three null-terminated strings: DisplayName, AddressType, EmailAddress.
    """
    if len(provider) < 4:
        out["display"] = out["addrtype"] = out["email"] = None
        return
    flags = int.from_bytes(provider[2:4], "little")
    unicode = bool(flags & _ONEOFF_FLAG_UNICODE)
    body = provider[4:]
    parts = _split_strings(body, unicode, count=3)
    out["unicode"] = unicode
    out["display"] = parts[0] if len(parts) > 0 else None
    out["addrtype"] = parts[1] if len(parts) > 1 else None
    out["email"] = parts[2] if len(parts) > 2 else None
    if out["addrtype"] and out["addrtype"].upper() == "SMTP":
        out["smtp"] = out["email"]


def _parse_addrbook(provider: bytes, out: dict[str, Any]) -> None:
    """Parse an address-book EntryID ([MS-OXCDATA] §2.2.4.1).

    Layout after the MAPIUID: ``Version`` (u32) + ``Type`` (u32) +
    null-terminated 8-bit X500 distinguished name.
    """
    if len(provider) >= 8:
        out["ab_version"] = int.from_bytes(provider[0:4], "little")
        out["ab_type"] = int.from_bytes(provider[4:8], "little")
        dn = _cstr8(provider[8:])
    else:
        dn = _cstr8(provider)
    out["dn"] = dn
    out["x500"] = dn


def _split_strings(body: bytes, unicode: bool, count: int) -> list[str]:
    """Split ``count`` consecutive null-terminated strings from ``body``."""
    parts: list[str] = []
    if unicode:
        cur = 0
        n = len(body)
        while len(parts) < count and cur < n:
            end = cur
            while end + 1 < n and not (body[end] == 0 and body[end + 1] == 0):
                end += 2
            chunk = body[cur:end]
            parts.append(chunk.decode("utf-16-le", "replace"))
            cur = end + 2
        return parts
    cur = 0
    n = len(body)
    while len(parts) < count and cur <= n:
        end = body.find(b"\x00", cur)
        if end == -1:
            parts.append(body[cur:].decode("latin-1", "replace"))
            break
        parts.append(body[cur:end].decode("latin-1", "replace"))
        cur = end + 1
    return parts


def _cstr8(body: bytes) -> str:
    """Decode a single null-terminated 8-bit string."""
    end = body.find(b"\x00")
    if end == -1:
        end = len(body)
    return body[:end].decode("latin-1", "replace")


def _hex(b: Any) -> str:
    if isinstance(b, (bytes, bytearray)):
        return bytes(b).hex()
    return ""
