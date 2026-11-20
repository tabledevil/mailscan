#!/usr/bin/env python3
"""Count-only inventory summary of a PST/OST: states, findings, scan statistics.

Prints no subjects, addresses, bodies or other content — only counts and
finding codes — so the output can be shared to diagnose a store.

    python3 -m pstforensic.tools.summary /path/to/store.pst
    python3 -m pstforensic.tools.summary --json /path/to/store.pst
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import asdict


def summarize(path: str, *, progress: bool = False) -> dict:
    from pstforensic import open_store

    t0 = time.time()
    store = open_store(path)
    hdr = store.nodedb.header
    out: dict = {
        "variant": store.variant.name,
        "wVer": hdr.wver,
        "crypt_method": hdr.crypt_method,
        "variant_evidence": hdr.variant_evidence,
    }

    def report(done: int, total: int) -> None:
        print(f"\rscan {100 * done // max(total, 1):3d}%", end="", file=sys.stderr)

    states, provs, findings = Counter(), Counter(), Counter()
    with_history = with_deleted_on = n = 0
    for item in store.iter_items(progress=report if progress else None):
        n += 1
        states[item.state] += 1
        provs[item.provenance] += 1
        findings.update(item.integrity.codes)
        with_history += bool(item.history)
        with_deleted_on += bool(item.deletion and item.deletion.deleted_on)
        if progress and n % 500 == 0:
            print(f"\ritems {n}", end="", file=sys.stderr)
    if progress:
        print(f"\ritems {n}", file=sys.stderr)
    out["items_by_state"] = dict(states)
    out["items_by_provenance"] = dict(provs)
    out["item_findings"] = dict(findings)
    out["items_with_history"] = with_history
    out["items_with_deleted_on"] = with_deleted_on
    out["store_findings"] = dict(Counter(f.code for f in store.integrity.findings))
    out["inventory"] = asdict(store.inventory_stats)
    out["scan"] = asdict(store.scan().stats)
    out["scan_complete"] = store.scan().complete
    out["folders"] = sum(1 for _ in store.folders())
    out["seconds"] = round(time.time() - t0, 1)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--progress", action="store_true", help="scan progress on stderr")
    a = ap.parse_args(argv)
    s = summarize(a.path, progress=a.progress)
    if a.json:
        print(json.dumps(s, indent=2, default=str))
        return 0
    for k, v in s.items():
        if isinstance(v, dict):
            print(f"{k}:")
            for kk, vv in sorted(v.items(), key=lambda kv: str(kv[0])):
                print(f"  {kk}: {vv}")
        else:
            print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
