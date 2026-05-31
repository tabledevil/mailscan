"""MS-OXPROPS property dictionary loader (PLAN §9.1).

Loads the shipped ``oxprops_data.json`` package data (offline, no runtime
download — goal G2) into an id->definition map and provides forward/reverse
lookups for analyst-readable property names and their canonical types.

Each entry maps a canonical property id (``int``) to a ``PropDef`` describing
the ``PidTag*`` canonical name ([MS-OXPROPS] 2.x), the property type code(s)
the property may appear as, and the property *set* GUID (``None`` for canonical
properties that live in no named-property set).

Unknown property ids resolve to ``None`` from :func:`name_for` / :func:`type_for`,
letting callers distinguish "unset" (id absent from a message) from "unknown"
(id not in the catalog) — see [PLAN] §9.1.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources

__all__ = [
    "PropDef",
    "PROPS",
    "NAME_TO_ID",
    "name_for",
    "type_for",
    "id_for_name",
    "definition_for",
    "is_known",
    "format_unknown",
]

_DATA_FILE = "oxprops_data.json"


@dataclass(frozen=True)
class PropDef:
    """A single MS-OXPROPS property definition.

    Attributes:
        prop_id: Canonical 16-bit property id (e.g. ``0x0037`` for Subject).
        name: Canonical ``PidTag*`` name ([MS-OXPROPS] 2.x).
        types: Type code(s) the property is defined as, as ints
            (e.g. ``[0x001F, 0x001E]`` for a Unicode/ANSI string).
        set: Property-set GUID string if the property belongs to a named set,
            else ``None`` for canonical properties.
    """

    prop_id: int
    name: str
    types: tuple[int, ...]
    set: str | None


def _parse_type(value: str | int) -> int:
    """Parse a type code that may be a hex string ("0x001F") or an int."""
    if isinstance(value, int):
        return value
    return int(value, 16)


def _load() -> tuple[dict[int, PropDef], dict[str, int]]:
    """Load the shipped JSON catalog into the id->PropDef and name->id maps.

    Reads ``oxprops_data.json`` as package data via :mod:`importlib.resources`
    (no filesystem path assumptions, no network). Keys beginning with ``_`` are
    metadata and skipped.

    Returns:
        A ``(props, name_to_id)`` pair.
    """
    raw = (
        resources.files(__package__)
        .joinpath(_DATA_FILE)
        .read_text(encoding="utf-8")
    )
    data = json.loads(raw)

    props: dict[int, PropDef] = {}
    name_to_id: dict[str, int] = {}
    for key, entry in data.items():
        if key.startswith("_"):
            continue
        prop_id = int(key, 16)
        types = tuple(_parse_type(t) for t in entry.get("types", []))
        pdef = PropDef(
            prop_id=prop_id,
            name=entry["name"],
            types=types,
            set=entry.get("set"),
        )
        props[prop_id] = pdef
        # First definition wins on a name collision (canonical names are unique
        # in MS-OXPROPS, but guard anyway for forward-compat).
        name_to_id.setdefault(pdef.name, prop_id)
    return props, name_to_id


PROPS: dict[int, PropDef]
NAME_TO_ID: dict[str, int]
PROPS, NAME_TO_ID = _load()


def name_for(prop_id: int) -> str | None:
    """Return the canonical ``PidTag*`` name for a property id, or ``None``.

    Args:
        prop_id: 16-bit canonical property id (the high word of a property tag).

    Returns:
        The canonical name (e.g. ``"PidTagSubject"``) or ``None`` if the id is
        not in the catalog.
    """
    pdef = PROPS.get(prop_id)
    return pdef.name if pdef is not None else None


def type_for(prop_id: int) -> tuple[int, ...] | None:
    """Return the defined type code(s) for a property id, or ``None``.

    Args:
        prop_id: 16-bit canonical property id.

    Returns:
        A tuple of type codes (ints) the property may appear as, or ``None`` if
        the id is unknown.
    """
    pdef = PROPS.get(prop_id)
    return pdef.types if pdef is not None else None


def id_for_name(name: str) -> int | None:
    """Reverse lookup: canonical ``PidTag*`` name -> property id, or ``None``.

    Args:
        name: A canonical ``PidTag*`` property name.

    Returns:
        The matching property id, or ``None`` if the name is not in the catalog.
    """
    return NAME_TO_ID.get(name)


def definition_for(prop_id: int) -> PropDef | None:
    """Return the full :class:`PropDef` for a property id, or ``None``."""
    return PROPS.get(prop_id)


def is_known(prop_id: int) -> bool:
    """Return ``True`` iff the property id is present in the catalog."""
    return prop_id in PROPS


def format_unknown(prop_id: int, prop_type: int) -> str:
    """Render a tag for an *unknown* property id as ``0xIIII:TTTT (undefined)``.

    Per [PLAN] §9.1, unknown tags are surfaced distinctly from unset ones.

    Args:
        prop_id: 16-bit property id.
        prop_type: 16-bit property type code.

    Returns:
        A display string such as ``"0x8042:001F (undefined)"``.
    """
    return f"0x{prop_id:04X}:{prop_type:04X} (undefined)"
