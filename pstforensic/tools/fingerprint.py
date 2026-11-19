#!/usr/bin/env python3
"""Content-free structural fingerprint of a PST/OST/NST file.

Purpose: find out *why* a store fails in readpst/libpff (and in pstforensic)
without any message content leaving the machine.  The output contains ONLY
format metadata: header fields, CRC verdicts, root offsets, B-tree page
counters/trailers and (optionally) a histogram of page/block trailers found
by a linear scan.  No property values, no strings, no data-block payloads.

stdlib only, so it can be copied onto an isolated/air-gapped machine:

    python3 fingerprint.py /path/to/store.pst            # header + root pages
    python3 fingerprint.py --scan /path/to/store.pst     # + full-file trailer scan
    python3 fingerprint.py --json /path/to/store.pst     # machine-readable

Offsets follow [MS-PST] §2.2.2.6 / PLAN Appendix A (see pstforensic/ndb/header.py).
4K-page (wVer 36/37) geometry is still a hypothesis in pstforensic, so for
those files the raw tail bytes of the root pages are printed as hex — they
hold only counters, ids and CRCs, and are exactly what we need to lock it.
"""
from __future__ import annotations

import argparse
import json
import mmap
import os
import struct
import sys
import zlib

MAGIC = b"!BDN"
CLIENT_MAGIC = {b"SM": "PST", b"SO": "OST", b"AB": "PAB"}
CRYPT = {0x00: "NONE", 0x01: "PERMUTE", 0x02: "CYCLIC", 0x10: "EDPCRYPTED(WIP)"}
PTYPE = {0x80: "BBT", 0x81: "NBT", 0x82: "FMap", 0x83: "PMap", 0x84: "AMap",
         0x85: "FPMap", 0x86: "DL"}


def ms_crc(data: bytes) -> int:
    """[MS-PST] §5.3 CRC: poly 0xEDB88320, seed 0, no final inversion.

    zlib.crc32 pre/post-inverts, so seeding it with 0xFFFFFFFF and inverting
    the result yields the raw table-driven value with seed 0.
    """
    return zlib.crc32(data, 0xFFFFFFFF) ^ 0xFFFFFFFF


def ms_sig(ib: int, bid: int) -> int:
    x = (ib ^ bid) & 0xFFFFFFFF
    return ((x >> 16) ^ x) & 0xFFFF


def variant_of(wver: int) -> dict | None:
    if wver in (14, 15):
        return dict(name="ansi", unicode=False, root=0xA4, crypt=0x1CD, w=4,
                    page=512, ptrail=12)
    if wver in (36, 37):
        return dict(name="unicode4k", unicode=True, root=0xB4, crypt=0x201, w=8,
                    page=4096, ptrail=None)  # trailer size unverified
    if wver >= 23:
        return dict(name="unicode", unicode=True, root=0xB4, crypt=0x201, w=8,
                    page=512, ptrail=16)
    return None


def u(buf, off, n):
    return int.from_bytes(buf[off:off + n], "little")


def parse_trailer(page: bytes, v: dict) -> dict:
    t = page[-16:] if v["unicode"] else page[-12:]
    d = dict(ptype=t[0], ptypeRepeat=t[1], wSig=u(t, 2, 2))
    if v["unicode"]:
        d["dwCRC"], d["bid"] = u(t, 4, 4), u(t, 8, 8)
    else:
        d["bid"], d["dwCRC"] = u(t, 4, 4), u(t, 8, 4)
    return d


def inspect_root_page(mm, size: int, ib: int, bid: int, expect: int, v: dict) -> dict:
    out: dict = {"ib": ib, "bid": bid, "in_file": ib + v["page"] <= size}
    if not out["in_file"]:
        return out
    page = bytes(mm[ib:ib + v["page"]])
    if v["ptrail"] is None:
        # 4K: geometry unverified -> raw tail (counters/ids/CRC only, no content)
        out["tail64_hex"] = page[-64:].hex()
        out["note"] = "4K geometry unverified; tail bytes recorded for locking"
        return out
    tr = parse_trailer(page, v)
    pad = 4 if v["unicode"] else 0
    base = v["page"] - v["ptrail"] - pad - 4
    out.update(
        ptype=PTYPE.get(tr["ptype"], hex(tr["ptype"])),
        ptype_ok=tr["ptype"] == expect and tr["ptype"] == tr["ptypeRepeat"],
        trailer_bid_matches_bref=tr["bid"] == bid,
        crc_ok=ms_crc(page[:v["page"] - v["ptrail"]]) == tr["dwCRC"],
        sig_ok=ms_sig(ib, tr["bid"]) == tr["wSig"],
        cEnt=page[base], cEntMax=page[base + 1], cbEnt=page[base + 2],
        cLevel=page[base + 3],
    )
    return out


def scan(mm, size: int, v: dict) -> dict:
    """Histogram of plausible B-tree/map page trailers on the page stride."""
    if v["ptrail"] is None:
        return {"skipped": "4K trailer geometry unverified"}
    # Spec says pages sit on 512B boundaries; we accept any 64B-aligned page
    # (as the recovery carver does) and count how many were 512-aligned.
    page, pt = v["page"], v["ptrail"]
    hist: dict[str, dict[str, int]] = {}
    max_bid = 0
    for t0, name in PTYPE.items():
        pat = bytes((t0, t0))
        pos = mm.find(pat, page - pt)
        while pos != -1:
            ib = pos - (page - pt)
            if ib % 64 == 0 and ib + page <= size:
                pg = bytes(mm[ib:ib + page])
                tr = parse_trailer(pg, v)
                if ms_sig(ib, tr["bid"]) == tr["wSig"]:
                    h = hist.setdefault(name, {"seen": 0, "crc_ok": 0, "aligned512": 0})
                    h["seen"] += 1
                    h["aligned512"] += ib % 512 == 0
                    h["crc_ok"] += ms_crc(pg[:page - pt]) == tr["dwCRC"]
                    if name in ("BBT", "NBT"):
                        max_bid = max(max_bid, tr["bid"])
            pos = mm.find(pat, pos + 1)
    return {"pages_with_valid_sig": hist, "max_btree_page_bid": max_bid}


def fingerprint(path: str, do_scan: bool = False) -> dict:
    size = os.path.getsize(path)
    fp: dict = {"file_size": size}
    with open(path, "rb") as fh:
        if size < 0x210:
            fp["error"] = "file smaller than a PST header"
            return fp
        mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            h = bytes(mm[:0x400])
            fp["magic_ok"] = h[:4] == MAGIC
            fp["client_magic"] = CLIENT_MAGIC.get(h[8:10], h[8:10].hex())
            wver = u(h, 0x0A, 2)
            fp["wVer"], fp["wVerClient"] = wver, u(h, 0x0C, 2)
            fp["bPlatformCreate"], fp["bPlatformAccess"] = h[0x0E], h[0x0F]
            fp["crc_partial_ok"] = ms_crc(h[8:8 + 471]) == u(h, 4, 4)
            v = variant_of(wver)
            if v is None:
                fp["error"] = f"unknown wVer {wver}"
                return fp
            fp["variant"] = v["name"]
            if v["unicode"]:
                fp["crc_full_ok"] = ms_crc(h[8:8 + 516]) == u(h, 0x20C, 4)
            cm = h[v["crypt"]]
            fp["bCryptMethod"] = CRYPT.get(cm, hex(cm))
            w, r = v["w"], v["root"] + 4
            vals = [u(h, r + i * w, w) for i in range(4)]
            r += 4 * w
            nbt_bid, nbt_ib = u(h, r, w), u(h, r + w, w)
            r += 2 * w
            bbt_bid, bbt_ib = u(h, r, w), u(h, r + w, w)
            r += 2 * w
            fp["root"] = {
                "ibFileEof": vals[0], "ibAMapLast": vals[1],
                "cbAMapFree": vals[2], "cbPMapFree": vals[3],
                "fAMapValid": h[r],
                "eof_vs_size": ("match" if vals[0] == size else
                                "file_truncated" if vals[0] > size else
                                "file_has_trailing_data"),
            }
            fp["nbt_root"] = inspect_root_page(mm, size, nbt_ib, nbt_bid, 0x81, v)
            fp["bbt_root"] = inspect_root_page(mm, size, bbt_ib, bbt_bid, 0x80, v)
            if do_scan:
                fp["scan"] = scan(mm, size, v)
        finally:
            mm.close()
    return fp


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path")
    ap.add_argument("--scan", action="store_true", help="linear trailer scan (slow on GB files)")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    fp = fingerprint(a.path, a.scan)
    if a.json:
        print(json.dumps(fp, indent=2))
    else:
        def show(d, ind=""):
            for k, val in d.items():
                if isinstance(val, dict):
                    print(f"{ind}{k}:")
                    show(val, ind + "  ")
                else:
                    print(f"{ind}{k}: {val}")
        show(fp)
    return 0


if __name__ == "__main__":
    sys.exit(main())
