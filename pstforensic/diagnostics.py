"""Content-free diagnostics for field reports (leak / evidence pipelines).

Everything here is safe to hand to a developer: exception *types* and the
pstforensic code location they came from, structural ids (NID, BID, file
offset), warning codes, timings, versions.  Never exception messages, property
values, names or bytes — a ``UnicodeDecodeError`` message alone can carry
mailbox content.
"""
from __future__ import annotations

import os
import platform
import subprocess
import sys
import time
import traceback
from collections import Counter
from contextlib import contextmanager
from typing import Optional

import logging as _logging

_log = _logging.getLogger("pstforensic.diag")
_PKG_DIR = os.path.dirname(os.path.abspath(__file__))
_SAMPLES = 5   # sample NIDs kept per failure signature


def code_location(exc: BaseException) -> str:
    """``module.py:line in func`` of the innermost pstforensic frame (plus the
    raising frame if that is outside the package)."""
    frames = traceback.extract_tb(exc.__traceback__)
    ours = [f for f in frames if os.path.abspath(f.filename).startswith(_PKG_DIR)]
    loc = ""
    if ours:
        f = ours[-1]
        loc = f"{os.path.relpath(f.filename, _PKG_DIR)}:{f.lineno} in {f.name}"
    if frames and (not ours or frames[-1] is not ours[-1]):
        f = frames[-1]
        loc += f" -> {os.path.basename(f.filename)}:{f.lineno} in {f.name}"
    return loc or "?"


class Diagnostics:
    """Aggregates failures by signature (phase, exception type, location)."""

    def __init__(self) -> None:
        self.failures: dict[tuple, dict] = {}
        self.reasons: Counter = Counter()     # e.g. unresolved:no_message_class
        self.timings: dict[str, float] = {}

    def failure(self, phase: str, exc: BaseException, *, nid: Optional[int] = None,
                bid: Optional[int] = None) -> None:
        key = (phase, type(exc).__name__, code_location(exc))
        if _log.isEnabledFor(10):
            frames = "".join(traceback.format_list(traceback.extract_tb(exc.__traceback__)))
            _log.debug("failure %s %s nid=%s bid=%s\n%s", phase, type(exc).__name__,
                       f"{nid:#x}" if nid is not None else "-",
                       f"{bid:#x}" if bid is not None else "-", frames.rstrip())
        rec = self.failures.setdefault(key, {"count": 0, "samples": []})
        rec["count"] += 1
        if len(rec["samples"]) < _SAMPLES:
            s = {}
            if nid is not None:
                s["nid"] = f"{nid:#x}"
            if bid is not None:
                s["bid"] = f"{bid:#x}"
            if s:
                rec["samples"].append(s)

    def reason(self, name: str) -> None:
        self.reasons[name] += 1

    @contextmanager
    def timed(self, phase: str):
        t0 = time.perf_counter()
        try:
            yield
        finally:
            self.timings[phase] = round(self.timings.get(phase, 0.0)
                                        + time.perf_counter() - t0, 3)

    def as_dict(self) -> dict:
        return {
            "failures": [
                {"phase": p, "exception": e, "location": loc, **rec}
                for (p, e, loc), rec in sorted(self.failures.items(),
                                               key=lambda kv: -kv[1]["count"])],
            "reasons": dict(self.reasons),
            "timings_s": dict(self.timings),
        }


def environment() -> dict:
    """Versions and platform — enough to reproduce."""
    from . import __version__
    env = {"pstforensic": __version__, "python": sys.version.split()[0],
           "platform": platform.platform(terse=True)}
    try:
        import numpy
        env["numpy"] = numpy.__version__
    except ImportError:
        env["numpy"] = None
    try:
        env["git_commit"] = subprocess.run(
            ["git", "-C", _PKG_DIR, "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5).stdout.strip() or None
    except Exception:
        env["git_commit"] = None
    return env


def peak_rss_mb() -> Optional[float]:
    try:
        import resource
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(rss / (1 << 20) if sys.platform == "darwin" else rss / 1024, 1)
    except Exception:
        return None


def warnings_summary(sink, limit: int = 30) -> dict:
    """Warning codes with counts, and the first locations (``where`` only —
    the free-text detail is withheld)."""
    codes = Counter(w.code for w in sink.warnings)
    where: dict[str, list] = {}
    for w in sink.warnings:
        lst = where.setdefault(w.code, [])
        if len(lst) < 5 and w.where and w.where not in lst:
            lst.append(w.where)
    top = dict(codes.most_common(limit))
    return {"counts": top, "first_locations": {c: where.get(c, []) for c in top}}
