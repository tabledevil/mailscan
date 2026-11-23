#!/usr/bin/env python3
"""Folder tree of a PST/OST the way Kernel PST Viewer shows it — for a
side-by-side comparison.

    python3 -m pstforensic.tools.tree store.pst              # tree + counts
    python3 -m pstforensic.tools.tree store.pst --items      # + item lists
    python3 -m pstforensic.tools.tree store.pst --redact     # shareable
    python3 -m pstforensic.tools.tree store.pst --json --redact > tree.json

Every folder line shows the count the folder itself declares
(PidTagContentCount) next to what was found, split by state, so gaps are
visible at a glance.  Items the folder walk could not place appear under
synthetic folders: ``~orphan folders/folder 0x…`` (grouped by the parent NID
their node names — Kernel's orphan folders), ``~lost``, ``~carved``.

Without ``--redact`` the output holds folder names and, with ``--items``,
senders and subjects: it is for the analyst's own screen.  ``--redact``
replaces every name by its NID and drops item text, leaving structure and
counts only.  Progress (stderr) and the ``--checkpoint`` file are always
content-free.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from typing import Optional

STATE_ORDER = ("live", "live_damaged", "soft_deleted", "orphan", "deleted",
               "superseded", "lost", "carved")
_ABBR = {"live": "live", "live_damaged": "dmg", "soft_deleted": "soft",
         "orphan": "orph", "deleted": "del", "superseded": "sup", "lost": "lost",
         "carved": "carv"}
_BYTE_PHASES = ("scan_pages", "scan_blocks")
_VISIBLE = ("live", "live_damaged", "soft_deleted")   # what a folder lists
PID_CONTENT_COUNT = 0x3602
PID_DISPLAY_NAME = 0x3001


# --------------------------------------------------------------------------
# progress (content-free)
# --------------------------------------------------------------------------
class Progress:
    """Phase-aware progress line on stderr plus an optional JSON checkpoint."""

    def __init__(self, *, enabled: bool, checkpoint: Optional[str] = None,
                 every: float = 5.0):
        self.enabled = enabled
        self.checkpoint = checkpoint
        self.every = every
        self.t0 = time.time()
        self.phase: Optional[str] = None
        self.phase_t0 = self.t0
        self.last_write = 0.0
        self.last_print = 0.0
        self.state: dict = {}

    def __call__(self, phase: str, done: int, total: Optional[int],
                 found: Optional[int]) -> None:
        now = time.time()
        if phase != self.phase:
            if self.enabled and self.phase is not None:
                print(file=sys.stderr)
            self.phase, self.phase_t0 = phase, now
        self.state = {"phase": phase, "done": done, "total": total, "found": found,
                      "elapsed_s": round(now - self.t0, 1),
                      "phase_elapsed_s": round(now - self.phase_t0, 1)}
        if self.enabled and (now - self.last_print > 0.2 or done == total):
            line = self._line(now)
            if line != getattr(self, "_last_line", None):
                self.last_print, self._last_line = now, line
                print("\r" + line, end="", file=sys.stderr)
        if self.checkpoint and now - self.last_write >= self.every:
            self.write_checkpoint()

    def _line(self, now: float) -> str:
        s = self.state
        done, total, found = s["done"], s["total"], s["found"]
        el = now - self.phase_t0
        if s["phase"] in _BYTE_PHASES:
            gb = 1 << 30
            rate = done / el / (1 << 20) if el > 0 else 0
            txt = f"[{s['phase']}] {done / gb:6.2f}/{total / gb:.2f} GB {rate:6.0f} MB/s"
        else:
            txt = f"[{s['phase']}] checked {done}"
            if total:
                txt += f"/{total} remaining {total - done}"
        if found is not None and s["phase"] not in _BYTE_PHASES:
            txt += f" found {found}"
        txt += f" elapsed {_hms(el)}"
        if total and done and el > 3 and done < total:
            txt += f" ETA ~{_hms(el * (total - done) / done)}"
        return txt.ljust(100)

    def write_checkpoint(self, status: str = "running") -> None:
        if not self.checkpoint:
            return
        self.last_write = time.time()
        try:
            with open(self.checkpoint, "w") as fh:
                json.dump({"status": status, **self.state}, fh)
        except OSError:
            pass

    def finish(self) -> None:
        if self.enabled and self.phase is not None:
            print(file=sys.stderr)
        self.state["elapsed_s"] = round(time.time() - self.t0, 1)
        self.write_checkpoint("complete")


def _hms(sec: float) -> str:
    sec = int(sec)
    return f"{sec // 3600}:{sec % 3600 // 60:02d}:{sec % 60:02d}"


# --------------------------------------------------------------------------
# tree building
# --------------------------------------------------------------------------
def _text(v) -> str:
    return "" if v is None else str(v)


def _folder_meta(store, nid: int) -> tuple[Optional[int], Optional[str]]:
    """(declared content count, display name) from the folder's own PC."""
    from pstforensic.ltp.pc import PropertyContext
    ref = store.nodedb.node(nid)
    if ref is None:
        return None, None
    try:
        pc = PropertyContext.from_node(ref, store.variant, sink=store.sink)
    except Exception:
        return None, None
    v = pc.by_id(PID_CONTENT_COUNT)
    declared = int.from_bytes(v.raw[:4], "little") if v is not None and v.raw else None
    n = pc.by_id(PID_DISPLAY_NAME)
    name = n.raw.decode("utf-16-le", "replace") if n is not None and n.raw else None
    return declared, name


def _item_row(item, redact: bool) -> dict:
    m = item.message
    row = {"state": item.state, "provenance": item.provenance,
           "nid": f"{item.nid:#x}" if item.nid else None,
           "bid": f"{item.bid:#x}" if item.bid else None,
           "findings": sorted(item.integrity.codes)}
    if m is not None:
        row["attachments"] = len(m.attachments)
        if not redact:
            row["date"] = _text(m.render(0x0E06) or m.render(0x0039)) or None
            row["from"] = _text(m.render(0x0C1A) or m.render(0x0C1F)) or None
            row["subject"] = item.subject
            row["class"] = _text(m.render(0x001A)) or None
    return row


def build_tree(path: str, *, items: bool = False, redact: bool = False,
               progress=None, cache_dir=None) -> dict:
    from pstforensic import open_store
    t0 = time.time()
    store = open_store(path, progress=progress, cache_dir=cache_dir)
    per_label: dict[str, Counter] = defaultdict(Counter)
    rows: dict[str, list] = defaultdict(list)
    for it in store.iter_items():
        label = it.folder_label
        per_label[label][it.state] += 1
        if items:
            rows[label].append(_item_row(it, redact))

    inv = store.inventory
    folder_paths = dict(inv.folder_paths) if inv is not None else {}
    path_nid = {p: n for n, p in folder_paths.items()}
    folders = []
    seen = set()
    for nid, fpath in folder_paths.items():   # walk order, like a tree view
        declared, _name = _folder_meta(store, nid)
        folders.append({"path": fpath, "nid": nid, "declared": declared,
                        "found": dict(per_label.get(fpath, {}))})
        seen.add(fpath)
    for label in sorted(per_label):           # synthetic / deleted-folder buckets
        if label not in seen:
            folders.append({"path": label, "nid": None, "declared": None,
                            "found": dict(per_label[label])})

    def shown(p: str) -> str:
        return redact_path(p, path_nid) if redact else p

    for f in folders:
        orig = f["path"]
        f["path"] = shown(orig)
        f["nid"] = f"{f['nid']:#x}" if f["nid"] is not None else None
        if items:
            f["items"] = rows.get(orig, [])
    hdr = store.nodedb.header
    return {
        "store": None if redact else store.display_name,
        "variant": store.variant.name, "wVer": hdr.wver,
        "file_size": store.nodedb.reader.size,
        "totals": dict(sum((Counter(f["found"]) for f in folders), Counter())),
        "folders": folders,
        "folder_reconstruction": _stats(store),
        "elapsed_s": round(time.time() - t0, 1),
    }


SYNTHETIC = ("~orphan folders", "~root")   # segments that are ours, not names


def redact_path(p: str, path_nid: dict) -> str:
    """Replace every real folder name by its NID; keep our synthetic labels
    (``~root``, ``~orphan folders/folder 0x…``, ``~carved`` …)."""
    segs = p.strip("/").split("/") if p.strip("/") else []
    acc, out = "", []
    for i, seg in enumerate(segs):
        acc += "/" + seg
        n = path_nid.get(acc)
        if n is not None:
            out.append(f"folder {n:#x}")
        elif seg.startswith("~") and (i == 0 or seg in SYNTHETIC):
            out.append(seg)
        elif i > 0 and segs[i - 1] == "~orphan folders" and seg.startswith("folder 0x"):
            out.append(seg)
        else:
            out.append("folder ?")
    return "/" + "/".join(out)


def _stats(store) -> dict:
    from dataclasses import asdict
    return asdict(store.inventory_stats) if store.inventory_stats else {}


# --------------------------------------------------------------------------
# text rendering
# --------------------------------------------------------------------------
def render_text(tree: dict, *, items: bool = False, out=sys.stdout) -> None:
    w = out.write
    w(f"{tree['store'] or '(store)'}  [{tree['variant']}, wVer {tree['wVer']}, "
      f"{tree['file_size'] / (1 << 30):.2f} GB]\n")
    tot = tree["totals"]
    w("items: " + ", ".join(f"{k}={tot[k]}" for k in STATE_ORDER if k in tot)
      + f"  (total {sum(tot.values())})\n\n")
    w(f"{'folder':60} {'declared':>8} {'listed':>6}  by state "
      "('!' = declared != listed)\n")
    w("-" * 100 + "\n")
    for f in tree["folders"]:
        parts = f["path"].strip("/").split("/") if f["path"].strip("/") else ["(root)"]
        name = "  " * (len(parts) - 1) + parts[-1]
        found = sum(n for k, n in f["found"].items() if k in _VISIBLE)
        dec = "" if f["declared"] is None else str(f["declared"])
        mark = " !" if f["declared"] is not None and f["declared"] != found else ""
        states = " ".join(f"{_ABBR[k]}={f['found'][k]}" for k in STATE_ORDER
                          if k in f["found"])
        w(f"{name[:60]:60} {dec:>8} {found:>6}{mark:2} {states}\n")
        if items:
            for r in f.get("items", []):
                ident = r.get("nid") or r.get("bid") or "-"
                if "subject" in r:
                    w(f"{'':6}{_text(r.get('date'))[:19]:19}  {_text(r.get('from'))[:24]:24}  "
                      f"{_text(r.get('subject'))[:60]:60}  [{r['state']}] "
                      f"att={r.get('attachments', 0)}\n")
                else:
                    w(f"{'':6}{ident:12} [{r['state']}/{r['provenance']}] "
                      f"att={r.get('attachments', 0)} {','.join(r['findings'])}\n")
    st = tree["folder_reconstruction"]
    if st:
        w("\nfolder reconstruction: " + ", ".join(
            f"{k}={v}" for k, v in st.items() if k.startswith(("folder", "contents", "orphans", "lost"))) + "\n")
    w(f"elapsed {tree['elapsed_s']} s\n")


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("path")
    ap.add_argument("--items", action="store_true", help="list items under each folder")
    ap.add_argument("--redact", action="store_true",
                    help="no names/subjects: NIDs and counts only (shareable)")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--no-progress", action="store_true")
    ap.add_argument("--checkpoint", help="write content-free progress JSON here")
    ap.add_argument("--debug-log", help="write the pstforensic debug log here")
    ap.add_argument("--profile", help="write a content-free CPU profile here")
    ap.add_argument("--cache-dir", default=None,
                    help="structural index cache (content-free; default ~/.cache/pstforensic)")
    ap.add_argument("--no-cache", action="store_true", help="do not read or write the cache")
    args = ap.parse_args(argv)
    if args.debug_log:
        from pstforensic.log import enable_debug_log
        enable_debug_log(args.debug_log)
    prog = Progress(enabled=not args.no_progress, checkpoint=args.checkpoint)
    from pstforensic.cache import default_dir
    cdir = None if args.no_cache else (args.cache_dir or default_dir())
    if args.profile:
        from pstforensic.diagnostics import run_profiled
        tree = run_profiled(build_tree, args.profile, args.path, items=args.items,
                            redact=args.redact, progress=prog, cache_dir=cdir)
    else:
        tree = build_tree(args.path, items=args.items, redact=args.redact, progress=prog,
                          cache_dir=cdir)
    prog.finish()
    if args.json:
        json.dump(tree, sys.stdout, indent=1, default=str)
        print()
    else:
        render_text(tree, items=args.items)
    return 0


if __name__ == "__main__":
    sys.exit(main())
