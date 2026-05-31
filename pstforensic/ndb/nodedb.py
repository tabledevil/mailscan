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
from ..variant import Variant
from .block import BlockReader
from .btree import BBTEntry, BTreeWalker, NBTEntry
from .header import Header, Root, detect
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

    def data_stream(self) -> bytes:
        """Decoded, reassembled data bytes of this node ([MS-PST] §2.2.2.8)."""
        if self._data is None:
            if not self.bid_data:
                self._data = b""
            else:
                self._data = self._db._block_reader.read_data_stream(self.bid_data)
        return self._data

    def subnodes(self) -> dict[int, "NodeRef"]:
        """Resolve the subnode tree to ``{local_nid: NodeRef}`` ([MS-PST] §2.2.2.8.3.3)."""
        if self._subnodes is None:
            result: dict[int, "NodeRef"] = {}
            for inner_nid, bdata, bsub in self._db._subnode_reader.iter_subnodes(self.bid_sub):
                result[inner_nid] = NodeRef(self._db, inner_nid, bdata, bsub,
                                            nid_parent=self.nid)
            self._subnodes = result
        return self._subnodes

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
        self.header: Header = detect(reader, sink=self.sink)
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

    # -- construction helpers --------------------------------------------
    @classmethod
    def open(cls, reader: FileReader, *, sink: WarningSink | None = None) -> "NodeDatabase":
        """Open and fully parse the store header/B-trees ([MS-PST] §2.2.2.6)."""
        return cls(reader, sink=sink)

    def _build_btrees(self) -> None:
        root: Root = self.header.root
        walker = BTreeWalker(self.reader, self.variant, sink=self.sink)
        for ent in walker.walk(root.bref_bbt, key_kind="BID"):
            self._bbt[ent.bid] = ent
        for ent in walker.walk(root.bref_nbt, key_kind="NID"):
            self._nbt[ent.nid] = ent

    # -- public surface ---------------------------------------------------
    def node(self, nid: int) -> Optional[NodeRef]:
        """Return a :class:`NodeRef` for ``nid``, or ``None`` if absent."""
        ent = self._nbt.get(nid)
        if ent is None:
            return None
        return NodeRef(self, ent.nid, ent.bid_data, ent.bid_sub, ent.nid_parent)

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
