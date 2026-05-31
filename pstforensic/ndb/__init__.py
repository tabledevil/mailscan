"""NDB (Node Database) layer — header, B-trees, blocks, decode, CRC."""
from .crc import compute_crc, compute_crc_bitwise, compute_sig
from .bref import (
    BREF,
    bid_is_internal,
    make_nid,
    nid_index,
    nid_type,
    normalize_bid,
)
from .crypt import decode_block, detect_encode, encode_block, mpbbCrypt
from .header import Header, Root, detect
from .nodedb import NodeDatabase, NodeRef

__all__ = [
    "compute_crc",
    "compute_crc_bitwise",
    "compute_sig",
    "BREF",
    "normalize_bid",
    "bid_is_internal",
    "nid_type",
    "nid_index",
    "make_nid",
    "decode_block",
    "encode_block",
    "detect_encode",
    "mpbbCrypt",
    "Header",
    "Root",
    "detect",
    "NodeDatabase",
    "NodeRef",
]
