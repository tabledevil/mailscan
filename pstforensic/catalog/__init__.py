"""pstforensic.catalog — the MAPI property dictionary and named-prop sets.

Layer-5/6 cross-cutting catalog (PLAN §9.1/§9.2):

* :mod:`pstforensic.catalog.oxprops` — the shipped MS-OXPROPS property
  dictionary (``PROPS``, :func:`oxprops.name_for`, :func:`oxprops.type_for`,
  reverse name->id).
* :mod:`pstforensic.catalog.namedprops` — well-known property-set GUIDs
  (:data:`namedprops.WELL_KNOWN_SETS`) and well-known LID labels
  (:func:`namedprops.lid_name`).

All data ships as package JSON; nothing is fetched at runtime (offline, G2).
"""
from __future__ import annotations

from . import namedprops, oxprops

__all__ = ["oxprops", "namedprops"]
