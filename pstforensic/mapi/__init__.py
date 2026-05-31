"""Shared MAPI object model."""
from .objects import (
    MapiAttachment,
    MapiMessage,
    MapiObject,
    MapiRecipient,
    MapiValue,
)

__all__ = [
    "MapiValue",
    "MapiObject",
    "MapiMessage",
    "MapiRecipient",
    "MapiAttachment",
]
