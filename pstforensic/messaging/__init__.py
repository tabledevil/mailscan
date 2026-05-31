"""pstforensic.messaging — the PST/OST messaging layer (PLAN §6).

Turns an NDB+LTP store into a navigable mail model:

  * :func:`open_store` → :class:`Store` (message-store PC, named-prop map, root).
  * :class:`Folder` — folder PC + hierarchy/contents/FAI TCs; lazy
    ``subfolders()`` / ``messages()`` with cycle guards.
  * Each message is a :class:`~pstforensic.mapi.MapiMessage` with recipients
    (Recipient TC 0x692), attachments (Attachment TC 0x671 → Attachment PCs) and
    recursively-parsed embedded messages.
  * :class:`~pstforensic.messaging.nameid.NamedPropMap` resolves named-property
    ids (``0x8000+``) from ``NID_NAME_TO_ID_MAP`` (0x61).
"""
from .store import Store, open_store
from .folder import Folder
from .nameid import NamedProp, NamedPropMap

__all__ = ["open_store", "Store", "Folder", "NamedProp", "NamedPropMap"]
