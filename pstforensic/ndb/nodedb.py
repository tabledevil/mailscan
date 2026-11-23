"""NodeDatabase — the NDB facade the LTP/messaging layers consume.

Parses header → variant → ROOT → NBT/BBT, then resolves nodes to decoded data
streams and their subnode trees.  This is the *only* NDB surface higher layers
touch (PLAN §4.7): ``NodeDatabase.node(nid) -> NodeRef`` with
``.data_stream()`` (decoded, reassembled across XBLOCK/XXBLOCK) and
``.subnodes()`` (a ``{local_nid: NodeRef}`` map).
"""
from __future__ import annotations

from typing import Iterator, Optional

from ..exceptions import WarningSink
from ..fileio import FileReader
from .. import integrity as I
from ..integrity import Integrity, weakest
from ..variant import Variant
from .block import BlockReader
from .btree import BBTEntry, BTreeWalker, NBTEntry
from ..exceptions import NotAPstError, UnsupportedStoreError
from .header import Header, Root, detect, headerless
from .subnode import SubnodeReader
import logging as _logging
import time as _time

_log = _logging.getLogger("pstforensic.ndb")


class NodeRef:
    """A handle to one node: its data stream and subnode children.

    ``data_stream()`` returns the decoded, reassembled bytes.  ``subnodes()``
    resolves the node's subnode tree to a ``{local_nid: NodeRef}`` map.
    """

    def __init__(self, db: "NodeDatabase", nid: int, bid_data: int,
                 bid_sub: int, nid_parent: int = 0):
        self.nid = nid
        self.bid_data = bid_data
        self.bid_sub = bid_sub
        self.nid_parent = nid_parent
        self._db = db
        self._data: Optional[bytes] = None
        self._segments: Optional[list[bytes]] = None
        self._subnodes: Optional[dict[int, "NodeRef"]] = None
        self.touched: set[int] = set()   # every BID this node's reads hit
        self.page_ib: Optional[int] = None  # NBT page the entry came from
        self.from_scan = False              # entry resolved by the full-file scan

    def data_stream(self) -> bytes:
        """Decoded, reassembled data bytes of this node ([MS-PST] §2.2.2.8)."""
        if self._data is None:
            self._data = b"".join(self.data_segments())
        return self._data

    def data_segments(self) -> list[bytes]:
        """The decoded data stream split at its on-disk leaf-block boundaries."""
        if self._segments is None:
            if not self.bid_data:
                self._segments = []
            else:
                self._segments = self._db._block_reader.read_data_segments(
                    self.bid_data, touched=self.touched)
        return self._segments

    def subnodes(self) -> dict[int, "NodeRef"]:
        """Resolve the subnode tree to ``{local_nid: NodeRef}`` ([MS-PST] §2.2.2.8.3.3)."""
        if self._subnodes is None:
            result: dict[int, "NodeRef"] = {}
            for inner_nid, bdata, bsub in self._db._subnode_reader.iter_subnodes(
                    self.bid_sub, touched=self.touched):
                result[inner_nid] = NodeRef(self._db, inner_nid, bdata, bsub,
                                            nid_parent=self.nid)
            self._subnodes = result
        return self._subnodes

    def integrity(self, *, deep: bool = True) -> Integrity:
        """Findings for every page/block this node (and, if ``deep``, its
        already-materialised subnodes) touched (PLAN §14.3)."""
        integ = Integrity()
        db = self._db
        pv = getattr(db, "page_verdicts", {}).get(self.page_ib) if self.page_ib is not None else None
        if pv is not None:
            integ.extend(pv.findings())
        if self.from_scan:
            integ.add(I.NODE_FROM_SCAN, "NBT entry found by the scan, not the B-tree",
                      nid=self.nid, ib=self.page_ib)
        br = db._block_reader
        for bid in sorted(self.touched):
            v = br.verdicts.get(bid)
            if v is not None:
                integ.extend(v.findings())
        sc = getattr(br, "stream_crypt", {}).get(self.bid_data)
        if sc is not None:
            method, level = sc
            integ.level = weakest((integ.level, level))
            if method != db.crypt_method:
                integ.add(I.CRYPT_FROM_EVIDENCE,
                          f"header bCryptMethod={db.crypt_method}; data decodes as {method}",
                          nid=self.nid)
            elif level == I.GUESSED:
                integ.add(I.CRYPT_GUESSED, nid=self.nid)
        if deep and self._subnodes:
            for child in self._subnodes.values():
                integ.merge(child.integrity(deep=True))
        return integ

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (f"NodeRef(nid={self.nid:#x}, bidData={self.bid_data:#x}, "
                f"bidSub={self.bid_sub:#x})")


class NodeDatabase:
    """Parsed NDB layer over a :class:`FileReader`."""

    def __init__(self, reader: FileReader, *, sink: WarningSink | None = None,
                 cache_dir: Optional[str] = None, cache_key: Optional[str] = None):
        self.reader = reader
        # NB: an *empty* WarningSink is falsy (its __len__ is 0), so use an
        # explicit None check — `sink or reader.sink` would silently discard a
        # caller's fresh sink.
        self.sink = sink if sink is not None else reader.sink
        try:
            self.header: Header = detect(reader, sink=self.sink)
        except (NotAPstError, UnsupportedStoreError) as exc:
            # Header unusable: open from the scan if the file holds B-tree
            # pages at all (Kernel reads such stores too) — else re-raise.
            self.header = headerless(reader, exc, sink=self.sink)
        self.variant: Variant = self.header.variant
        self.crypt_method: int = self.header.crypt_method

        # Build NBT/BBT indexes eagerly (cached for the life of the db, and
        # across runs when a cache directory is configured).
        from ..cache import IndexCache
        self.cache = IndexCache.for_reader(reader, cache_dir, cache_key)
        self._bbt: dict[int, BBTEntry] = {}
        self._nbt: dict[int, NBTEntry] = {}
        cached = self.cache.load("btree") if self.cache else None
        if cached is not None:
            (self._nbt, self._bbt, self.page_verdicts, self.skipped, warns) = cached
            self.sink.warnings.extend(warns)
        else:
            mark = len(self.sink.warnings)
            self._build_btrees()
            if self.cache:
                self.cache.save("btree", (self._nbt, self._bbt, self.page_verdicts,
                                          self.skipped, self.sink.warnings[mark:]))

        self._block_reader = BlockReader(
            reader, self.variant, bbt=self._bbt, sink=self.sink,
            crypt_method=self.crypt_method)
        self._subnode_reader = SubnodeReader(
            self._block_reader, self.variant, sink=self.sink)
        self._scan = None
        self._scan_nodes: dict[int, NBTEntry] = {}

    # -- full-file scan (PLAN §14.5) ---------------------------------------
    @property
    def nbt_damaged(self) -> bool:
        """The live NBT walk is known to be incomplete (NBT evidence only —
        a damaged BBT is recovered block-wise by the scan, issue #4)."""
        if not self._nbt or self.skipped["NBT"] or not self.header.root.bref_nbt.ib:
            return True
        v = self.page_verdicts.get(self.header.root.bref_nbt.ib)
        return v is None or not (v.ptype_ok and v.geometry_ok)

    @property
    def bbt_damaged(self) -> bool:
        """The live BBT walk is known to be incomplete."""
        if not self._bbt or self.skipped["BBT"] or not self.header.root.bref_bbt.ib:
            return True
        v = self.page_verdicts.get(self.header.root.bref_bbt.ib)
        return v is None or not (v.ptype_ok and v.geometry_ok)

    @property
    def skipped_pages(self) -> list[int]:
        return self.skipped["NBT"] + self.skipped["BBT"]

    def btree_damage(self) -> dict:
        """Per-tree damage summary — structural metadata only."""
        out = {}
        for tree in ("NBT", "BBT"):
            vs = [v for v in self.page_verdicts.values() if v.tree == tree]
            bad = [v for v in vs if v.findings()]
            skipped = set(self.skipped[tree])
            out[tree] = {
                "damaged": self.nbt_damaged if tree == "NBT" else self.bbt_damaged,
                "pages_read": len(vs), "pages_damaged": len(bad),
                "pages_skipped": len(skipped),
                "pages_zeroed": sum(1 for v in bad if v.zeroed),
                "skipped_samples": [
                    {"ib": f"{v.ib:#x}", "depth": v.depth,
                     "parent_ib": f"{v.parent_ib:#x}" if v.parent_ib is not None else None,
                     "zeroed": v.zeroed, "ptype": f"{v.ptype:#x}"}
                    for v in sorted(bad, key=lambda v: v.ib) if v.ib in skipped][:20],
            }
        return out

    def scan(self, *, progress=None, should_abort=None, use_numpy=None,
             deep: bool = False, workers=None):
        """Run (once) the full-file scan and wire it into resolution.

        Default profile is Kernel's: the store's own variant when the header
        proves it, pages on 512-byte boundaries.  ``deep`` scans every
        variant and every 64-byte boundary (shifted / foreign copies).
        ``workers``: scan processes (default: all cores for multi-GB files).

        Afterwards BIDs missing from the BBT resolve from block trailers, and
        :meth:`node` resolves NIDs missing from the NBT from the newest
        scanned entry (``from_scan``).
        """
        if self._scan is None or not self._scan.complete:
            from .scan import scan_file, _np
            if _np is None and use_numpy is not False and self.reader.size > (256 << 20):
                _log.warning("scan: numpy not installed — pure-Python scan of %d MiB "
                             "is much slower (pip install numpy, or the 'pst' extra)",
                             self.reader.size >> 20)
            _log.info("scan: start (%d bytes, store variant %s, nbt_damaged=%s)",
                      self.reader.size, self.variant.name, self.nbt_damaged)
            t0 = _time.perf_counter()
            from ..integrity import VERIFIED
            from ..variant import ANSI, UNICODE, UNICODE_4K
            proven = (self.header.variant_evidence or {}).get(self.variant.name) == VERIFIED
            variants = (self.variant,) if (proven and not deep) else (ANSI, UNICODE, UNICODE_4K)
            from .scan import default_workers
            n_workers = default_workers(self.reader.size) if workers is None else workers
            _log.info("scan: variants=%s page_stride=%d workers=%d",
                      [v.name for v in variants], 64 if deep else 512, n_workers)
            params = ([v.name for v in variants], 64 if deep else 512)
            cached = self.cache.load("scan", params) if self.cache else None
            if cached is not None:
                self._scan = cached
                if progress is not None:
                    progress(2 * self.reader.size, 2 * self.reader.size)
            else:
                self._scan = scan_file(
                    self.reader, self.variant, live_nbt=self._nbt, live_bbt=self._bbt,
                    live_page_ibs=set(self.page_verdicts), use_numpy=use_numpy,
                    progress=progress, should_abort=should_abort, variants=variants,
                    page_stride=64 if deep else 512, workers=n_workers)
                if self.cache and self._scan.complete:
                    self.cache.save("scan", self._scan, params)
            self._block_reader.attach_scan(self._scan.locate)
            self._scan_nodes = {}
            rank: dict[int, tuple] = {}
            for slot in self._scan.slots:
                if slot.variant != self.variant.name:
                    continue
                ent = slot.entry
                key = (not slot.beyond_cent, slot.page_bid)
                if ent.nid not in rank or key > rank[ent.nid]:
                    rank[ent.nid] = key
                    self._scan_nodes[ent.nid] = ent
            st = self._scan.stats
            _log.info("scan: done in %.1fs complete=%s pages=%d slots=%d blocks=%d "
                      "bbt_entries=%d stats=%s", _time.perf_counter() - t0,
                      self._scan.complete, len(self._scan.pages), len(self._scan.slots),
                      sum(len(v) for v in self._scan.blocks.values()),
                      len(self._scan.bbt_entries), st)
        return self._scan

    def scan_entry(self, nid: int) -> Optional[NBTEntry]:
        """Newest scanned NBT entry for ``nid`` (live page copies preferred)."""
        return self._scan_nodes.get(nid)

    # -- construction helpers --------------------------------------------
    @classmethod
    def open(cls, reader: FileReader, *, sink: WarningSink | None = None,
             cache_dir: Optional[str] = None,
             cache_key: Optional[str] = None) -> "NodeDatabase":
        """Open and fully parse the store header/B-trees ([MS-PST] §2.2.2.6)."""
        return cls(reader, sink=sink, cache_dir=cache_dir, cache_key=cache_key)

    def _build_btrees(self) -> None:
        root: Root = self.header.root
        walker = BTreeWalker(self.reader, self.variant, sink=self.sink)
        if not root.bref_nbt.ib:          # headerless: nothing to walk
            self.page_verdicts, self.skipped = {}, {"NBT": [], "BBT": []}
            return
        for ent in walker.walk(root.bref_bbt, key_kind="BID"):
            self._bbt[ent.bid] = ent
        for ent in walker.walk(root.bref_nbt, key_kind="NID"):
            self._nbt[ent.nid] = ent
        self.page_verdicts = walker.page_verdicts
        self.skipped = walker.skipped
        if not self._nbt and not self.skipped["NBT"]:
            self.skipped["NBT"] = [root.bref_nbt.ib]
        bad = {ib: sorted(f.code for f in v.findings())
               for ib, v in self.page_verdicts.items() if v.findings()}
        _log.info("btree: nbt=%d bbt=%d pages=%d damaged_pages=%d skipped_nbt=%d "
                  "skipped_bbt=%d", len(self._nbt), len(self._bbt),
                  len(self.page_verdicts), len(bad), len(self.skipped["NBT"]),
                  len(self.skipped["BBT"]))
        for ib, codes in list(bad.items())[:200]:
            v = self.page_verdicts[ib]
            _log.debug("btree: %s page %#x depth=%d parent=%s zeroed=%s %s", v.tree, ib,
                       v.depth, f"{v.parent_ib:#x}" if v.parent_ib is not None else "-",
                       v.zeroed, codes)

    # -- public surface ---------------------------------------------------
    def node(self, nid: int) -> Optional[NodeRef]:
        """Return a :class:`NodeRef` for ``nid``, or ``None`` if absent."""
        ent = self._nbt.get(nid)
        if ent is not None:
            return self.node_from_entry(ent)
        ent = self._scan_nodes.get(nid)
        if ent is None:
            return None
        ref = self.node_from_entry(ent)
        ref.from_scan = True
        return ref

    def node_from_entry(self, ent: NBTEntry) -> NodeRef:
        """A :class:`NodeRef` for any NBT entry — live or harvested by the scan."""
        ref = NodeRef(self, ent.nid, ent.bid_data, ent.bid_sub, ent.nid_parent)
        ref.page_ib = ent.page_ib
        return ref

    def iter_nbt(self) -> Iterator[NBTEntry]:
        """Iterate all leaf NBT entries ([MS-PST] §2.2.2.7.7.4)."""
        return iter(self._nbt.values())

    def iter_bbt(self) -> Iterator[BBTEntry]:
        """Iterate all leaf BBT entries ([MS-PST] §2.2.2.7.7.3)."""
        return iter(self._bbt.values())

    # -- recovery aid -----------------------------------------------------
    def free_region_info(self) -> dict:
        """Expose ROOT free-space hints for the recovery tier (advisory).

        Returns the ROOT's ``ib_file_eof``/``ib_amap_last``/``cb_amap_free``
        and the union of live block extents (``[ib, ib+disk)``) so the recovery
        engine can compute "not covered by rebuilt BBT" free space (H14) without
        re-walking.  AMap parsing proper is left to the recovery tier.
        """
        from .block import block_disk_size
        live = []
        for ent in self._bbt.values():
            live.append((ent.bref.ib, block_disk_size(ent.cb, self.variant)))
        return {
            "ib_file_eof": self.header.root.ib_file_eof,
            "ib_amap_last": self.header.root.ib_amap_last,
            "cb_amap_free": self.header.root.cb_amap_free,
            "f_amap_valid": self.header.root.f_amap_valid,
            "live_block_extents": live,
        }
