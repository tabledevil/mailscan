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
        self._subnodes: Optional[dict[int, "NodeRef"]] = None
        self.touched: set[int] = set()   # every BID this node's reads hit
        self.page_ib: Optional[int] = None  # NBT page the entry came from
        self.from_scan = False              # entry resolved by the full-file scan

    def data_stream(self) -> bytes:
        """Decoded, reassembled data bytes of this node ([MS-PST] §2.2.2.8)."""
        if self._data is None:
            if not self.bid_data:
                self._data = b""
            else:
                self._data = self._db._block_reader.read_data_stream(
                    self.bid_data, touched=self.touched)
        return self._data

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

    def __init__(self, reader: FileReader, *, sink: WarningSink | None = None):
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

        # Build NBT/BBT indexes eagerly (cached for the life of the db).
        self._bbt: dict[int, BBTEntry] = {}
        self._nbt: dict[int, NBTEntry] = {}
        self._build_btrees()

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
        """The live NBT walk is known to be incomplete."""
        if not self._nbt or self.skipped_pages or not self.header.root.bref_nbt.ib:
            return True
        v = self.page_verdicts.get(self.header.root.bref_nbt.ib)
        return v is None or not (v.ptype_ok and v.geometry_ok)

    def scan(self, *, progress=None, should_abort=None, use_numpy=None):
        """Run (once) the full-file scan and wire it into resolution.

        Afterwards BIDs missing from the BBT resolve from block trailers, and
        :meth:`node` resolves NIDs missing from the NBT from the newest
        scanned entry (``from_scan``).
        """
        if self._scan is None or not self._scan.complete:
            from .scan import scan_file
            self._scan = scan_file(
                self.reader, self.variant, live_nbt=self._nbt, live_bbt=self._bbt,
                live_page_ibs=set(self.page_verdicts), use_numpy=use_numpy,
                progress=progress, should_abort=should_abort)
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
        return self._scan

    def scan_entry(self, nid: int) -> Optional[NBTEntry]:
        """Newest scanned NBT entry for ``nid`` (live page copies preferred)."""
        return self._scan_nodes.get(nid)

    # -- construction helpers --------------------------------------------
    @classmethod
    def open(cls, reader: FileReader, *, sink: WarningSink | None = None) -> "NodeDatabase":
        """Open and fully parse the store header/B-trees ([MS-PST] §2.2.2.6)."""
        return cls(reader, sink=sink)

    def _build_btrees(self) -> None:
        root: Root = self.header.root
        walker = BTreeWalker(self.reader, self.variant, sink=self.sink)
        if not root.bref_nbt.ib:          # headerless: nothing to walk
            self.page_verdicts, self.skipped_pages = {}, []
            return
        for ent in walker.walk(root.bref_bbt, key_kind="BID"):
            self._bbt[ent.bid] = ent
        for ent in walker.walk(root.bref_nbt, key_kind="NID"):
            self._nbt[ent.nid] = ent
        self.page_verdicts = walker.page_verdicts
        self.skipped_pages = walker.skipped_pages
        if not self._nbt and not self.skipped_pages:
            self.skipped_pages = [root.bref_nbt.ib]

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
