"""Deep salvage of one item — ``item.recover()`` (PLAN §14.8).

The default inventory already returns damaged items with everything readable
plus findings.  Salvage is the expensive extra step for an item that matters:

  1. **Alternate copies** — every block the item read that did not verify is
     re-read from a verified on-disk copy of the same BID, if the scan found
     one (``RECOVERED_ALT_COPY``).
  2. **Older versions** — the item's ``superseded`` versions, newest first.
  3. **Fragments** — text runs (UTF-16LE and 8-bit) scraped from the raw
     bytes of every block the item touched.  Fragments are evidence, never a
     message.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .. import integrity as I
from .inventory import Item, all_touched

_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e\xa0-\xff]\x00){8,}")
_BYTE_RUN = re.compile(rb"[\x20-\x7e\xa0-\xff]{16,}")


@dataclass
class Salvage:
    item: Item                                   # best re-read (or the original)
    alternatives: list[Item] = field(default_factory=list)   # older versions
    fragments: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


def _fragments(raw: bytes) -> list[str]:
    out = [m.group().decode("utf-16-le") for m in _UTF16_RUN.finditer(raw)]
    out += [m.group().decode("cp1252", "replace") for m in _BYTE_RUN.finditer(raw)
            if b"\x00" not in m.group()]
    return out


def salvage(store, item: Item) -> Salvage:
    db = store.nodedb
    br = db._block_reader
    scan = store.scan()
    result = Salvage(item=item)

    # 2. older versions of the same NID, newest (highest BID) first
    pool = getattr(store, "_last_items", None) or []
    result.alternatives = sorted(
        (i for i in pool if i.state == "superseded" and item.nid and i.nid == item.nid
         and i is not item),
        key=lambda i: i.entry.bid_data if i.entry is not None else 0, reverse=True)

    # 1. re-read with verified alternate copies of unverified blocks
    ref = None
    if item.entry is not None:
        ref = db.node_from_entry(item.entry)
    elif item.nid:
        ref = db.node(item.nid)
    if ref is not None:
        try:
            ref.data_stream()
            ref.subnodes()
        except Exception:
            pass
        touched = all_touched(ref)
        prefer = {}
        for bid in touched:
            v = br.verdicts.get(bid)
            if v is not None and v.verified:
                continue
            for c in scan.copies(bid):
                if c.strong and c.ib != (v.ib if v is not None else None):
                    prefer[bid] = (c.ib, c.cb)
                    break
        if prefer:
            saved = {b: br.verdicts.get(b) for b in prefer}
            br.prefer.update(prefer)
            try:
                from .inventory import Inventory
                inv = Inventory(store, scan)
                fresh = db.node_from_entry(item.entry) if item.entry is not None \
                    else db.node(item.nid)
                msg = inv._build(fresh)
            finally:
                for b in prefer:
                    br.prefer.pop(b, None)
                    if saved[b] is None:
                        br.verdicts.pop(b, None)
                    else:
                        br.verdicts[b] = saved[b]
            if msg is not None:
                integ = msg.integrity or I.Integrity()
                for b, (ib, _cb) in prefer.items():
                    integ.add(I.RECOVERED_ALT_COPY, "verified copy used", bid=b, ib=ib)
                result.item = Item(nid=item.nid, state=item.state,
                                   provenance=item.provenance, message=msg,
                                   folder_path=item.folder_path, integrity=integ,
                                   deletion=item.deletion, history=item.history,
                                   supersedes=item.supersedes, entry=item.entry,
                                   _store=store)
                result.notes.append(f"{len(prefer)} block(s) re-read from verified copies")
    else:
        touched = {item.bid} if item.bid else set()

    # 3. fragments from every touched block's raw bytes
    from ..ndb.crypt import decode_block
    seen: set[str] = set()
    for bid in sorted(touched):
        loc = br.locate(bid)
        if loc is None:
            continue
        ib, cb, _ = loc
        raw = db.reader.read(ib, cb)
        method = br.stream_crypt.get(bid, (br.crypt_order[0], None))[0]
        for text in _fragments(decode_block(raw, method, bid) if not bid & 0x2 else raw):
            if text not in seen:
                seen.add(text)
                result.fragments.append(text)
    return result
