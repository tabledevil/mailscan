"""The shared MAPI object model (layer 5).

Both the PST/OST messaging layer and the native MSG parser build these exact
types, so every renderer/catalog capability works identically across formats
(PLAN §2.1 / G6). Values are stored lazily: a :class:`MapiValue` keeps the raw
bytes plus the property type and only decodes to a Python value on demand.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Optional

from ..proptypes import PropType, split_tag, tag_str


@dataclass
class MapiValue:
    """One property value: raw bytes + type, decoded lazily/by a renderer."""

    tag: int                      # (prop_id<<16)|prop_type
    raw: bytes
    # For MV types, ``raw`` is the concatenated source; ``elements`` holds the
    # split element byte-strings once parsed by the LTP/MSG reader.
    elements: Optional[list[bytes]] = None
    encoding: Optional[str] = None  # filled by the string renderer when relevant
    _decoded: Any = None
    _decoded_set: bool = False

    @property
    def prop_id(self) -> int:
        return (self.tag >> 16) & 0xFFFF

    @property
    def prop_type(self) -> int:
        return self.tag & 0xFFFF

    def set_decoded(self, value: Any) -> Any:
        self._decoded = value
        self._decoded_set = True
        return value

    @property
    def decoded(self) -> Any:
        return self._decoded if self._decoded_set else None

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return f"MapiValue({tag_str(self.tag)}, {len(self.raw)}B)"


@dataclass
class MapiObject:
    """A bag of MAPI properties keyed by full tag, with helpers.

    Subclasses (:class:`MapiMessage`, recipients, attachments) add typed
    accessors but the property store is uniform.
    """

    props: dict[int, MapiValue] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)  # WarnCode strings seen for this object
    nid: Optional[int] = None                      # source NID (PST) if any

    # Renderer is injected by the catalog/render layer to avoid an import cycle.
    _renderer: Optional[Callable[["MapiObject", int], Any]] = None

    def add(self, value: MapiValue) -> None:
        self.props[value.tag] = value

    def has(self, prop_id: int) -> bool:
        return any((t >> 16) == prop_id for t in self.props)

    def by_id(self, prop_id: int) -> Optional[MapiValue]:
        """First value with this property id, regardless of type."""
        for tag, v in self.props.items():
            if (tag >> 16) == prop_id:
                return v
        return None

    def get_tag(self, tag: int) -> Optional[MapiValue]:
        return self.props.get(tag)

    def raw_of(self, prop_id: int) -> Optional[bytes]:
        v = self.by_id(prop_id)
        return v.raw if v else None

    def render(self, prop_id_or_tag: int) -> Any:
        """Human-readable value via the injected renderer (set by render layer)."""
        v = self.props.get(prop_id_or_tag) or self.by_id(prop_id_or_tag)
        if v is None:
            return None
        if self._renderer is not None:
            return self._renderer(self, v.tag)
        return v.decoded if v._decoded_set else v.raw

    def tags(self) -> Iterator[int]:
        return iter(self.props)

    def __len__(self) -> int:
        return len(self.props)


@dataclass
class MapiRecipient(MapiObject):
    recipient_type: Optional[int] = None  # 1=To, 2=Cc, 3=Bcc (PidTagRecipientType)


@dataclass
class MapiAttachment(MapiObject):
    method: Optional[int] = None          # PidTagAttachMethod (5=embedded, 6=OLE)
    embedded: Optional["MapiMessage"] = None
    # ``open_data`` streams the attachment bytes lazily (set by the reader).
    open_data: Optional[Callable[[], bytes]] = None


@dataclass
class MapiMessage(MapiObject):
    recipients: list[MapiRecipient] = field(default_factory=list)
    attachments: list[MapiAttachment] = field(default_factory=list)
    embedded_messages: list["MapiMessage"] = field(default_factory=list)
    # Recovery provenance (None for live items); set by the recovery engine.
    recovery: Any = None
