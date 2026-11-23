#!/usr/bin/env python3
"""Count-only inventory summary of a PST/OST: states, findings, scan statistics.

Prints no subjects, addresses, bodies or other content — only counts and
finding codes — so the output can be shared to diagnose a store.

    python3 -m pstforensic.tools.summary /path/to/store.pst
    python3 -m pstforensic.tools.summary --json /path/to/store.pst
    python3 -m pstforensic.tools.summary --json --debug-log run.log /path/to/store.pst

The ``diagnostics`` section (and the debug log) hold only structural data:
exception types and code locations, NIDs/BIDs/offsets, warning codes,
timings, versions — safe to share for debugging.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from dataclasses import asdict


def summarize(path: str, *, progress: bool = False, cache_dir=None) -> dict:
    """Count-only summary.  Never raises: a failing phase is reported with the
    exception type and code location (no message text) plus a header
    fingerprint, so a field report is always produced."""
    from pstforensic import open_store
    from pstforensic.diagnostics import code_location, environment, peak_rss_mb

    t0 = time.time()
    try:
        store = open_store(path, cache_dir=cache_dir)
    except Exception as exc:
        out = {"failed_phase": "open", "exception": type(exc).__name__,
               "location": code_location(exc), "environment": environment(),
               "peak_rss_mb": peak_rss_mb()}
        try:
            from pstforensic.tools.fingerprint import fingerprint
            out["fingerprint"] = fingerprint(path, do_scan=False)
        except Exception as fexc:
            out["fingerprint_error"] = type(fexc).__name__
        return out
    try:
        return _summarize_store(store, path, progress, t0)
    except Exception as exc:
        return {"failed_phase": "inventory", "exception": type(exc).__name__,
                "location": code_location(exc), "diagnostics": store.diagnostics()}


def _summarize_store(store, path: str, progress: bool, t0: float) -> dict:
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
    out["diagnostics"] = store.diagnostics()
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--progress", action="store_true", help="scan progress on stderr")
    ap.add_argument("--cache-dir", default=None,
                    help="structural index cache (content-free; default ~/.cache/pstforensic)")
    ap.add_argument("--no-cache", action="store_true", help="do not read or write the cache")
    ap.add_argument("--profile", metavar="FILE",
                    help="write a content-free CPU profile (function names/times) here")
    ap.add_argument("--debug-log", metavar="FILE",
                    help="write the library's content-free DEBUG log to FILE")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="library log on stderr (-v INFO, -vv DEBUG)")
    a = ap.parse_args(argv)
    import logging
    from pstforensic.log import enable_debug_log
    if a.debug_log:
        enable_debug_log(a.debug_log, logging.DEBUG)
    if a.verbose:
        enable_debug_log(None, logging.DEBUG if a.verbose > 1 else logging.INFO)
    from pstforensic.cache import default_dir
    cdir = None if a.no_cache else (a.cache_dir or default_dir())
    if a.profile:
        from pstforensic.diagnostics import run_profiled
        s = run_profiled(summarize, a.profile, a.path, progress=a.progress, cache_dir=cdir)
    else:
        s = summarize(a.path, progress=a.progress, cache_dir=cdir)
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
