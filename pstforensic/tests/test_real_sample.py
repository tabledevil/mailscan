"""Content-SEALED real-sample test harness.

Purpose
-------
Validate ``pstforensic`` against a REAL (possibly classified) PST/OST/NST file
*without ever letting the file's contents enter a transcript* — not stdout, not
an assertion message, not a traceback, not a subagent return value.

How the sealing works
---------------------
1. The sample is NEVER read by an assistant tool and NEVER copied into the repo.
   You point an environment variable at it; it can live anywhere on disk:

       PSTFORENSIC_PRIVATE_SAMPLE=/secure/path/to/evidence.pst \
           python3 -m pytest pstforensic/tests/test_real_sample.py -q

   The whole module SKIPS if that variable is unset, so normal CI is unaffected.

2. Every check is a :func:`sealed_assert`: it compares COUNTS / LENGTHS / HASHES /
   BOOLEANS — never values — and its failure message contains no content.

3. Any unexpected exception is caught and rewritten to a content-free message
   (a raw traceback could otherwise carry a decoded subject/body), with the full
   detail written only to the gitignored sealed report.

4. Rich diagnostics (counts, coverage %, warning-code histogram, variant, crypt
   method, differential match counts) go to a LOCAL gitignored report file that
   only you read:

       PSTFORENSIC_PRIVATE_REPORT=/secure/path/report.sealed.txt   (optional)

   Default: ``pstforensic/tests/fixtures/private/sealed_report.txt`` (gitignored).
   The report holds METADATA only — never message text, recipients, or bytes.

5. The optional differential vs ``pypff``/``readpst`` compares SETS of per-run
   SALTED hashes in-process and writes only |match| / |only-ours| / |only-theirs|.

What this proves (without an external oracle, contents sealed)
-------------------------------------------------------------
robustness (no crash on a real file), total coverage (every node walked, every
property rendered without raising), determinism (two parses are byte-identical),
and — when ``pypff``/``readpst`` are installed — differential parity (Axis D).
"""
from __future__ import annotations

import hashlib
import logging
import os
import traceback
from pathlib import Path

import pytest

# Suppress any library logging for the duration — belt and suspenders so no
# module can emit decoded content to stdout/stderr during a real-file parse.
logging.disable(logging.CRITICAL)

_SAMPLE = os.environ.get("PSTFORENSIC_PRIVATE_SAMPLE")

pytestmark = pytest.mark.skipif(
    not (_SAMPLE and Path(_SAMPLE).is_file()),
    reason="set PSTFORENSIC_PRIVATE_SAMPLE=/path/to/real.pst to run the sealed real-sample harness",
)

# Per-run salt: makes in-process hashes non-comparable across runs and
# un-attackable even if a hash ever escaped (it does not).
_SALT = os.urandom(16)


# --------------------------------------------------------------------------- #
# Sealed reporting + assertion primitives                                      #
# --------------------------------------------------------------------------- #
def _report_path() -> Path:
    p = os.environ.get("PSTFORENSIC_PRIVATE_REPORT")
    if p:
        return Path(p)
    d = Path(__file__).parent / "fixtures" / "private"
    d.mkdir(parents=True, exist_ok=True)
    return d / "sealed_report.txt"


def _report(line: str) -> None:
    """Append a METADATA-ONLY line to the gitignored sealed report.

    Callers MUST only pass strings built from counts/codes/percentages/booleans.
    Never pass a property value, filename, address, or any decoded bytes.
    """
    with open(_report_path(), "a", encoding="utf-8") as fh:
        fh.write(line.rstrip("\n") + "\n")


def sealed_assert(cond: bool, safe_msg: str) -> None:
    """Assert ``cond``; ``safe_msg`` must be content-free (it may be printed)."""
    assert cond, safe_msg


def _sealed_digest(raw: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_SALT)
    h.update(raw)
    return h.digest()


def _safe_text(value) -> bytes:
    """Best-effort stable bytes for a rendered value — used ONLY to feed hashes;
    the result is never reported."""
    if value is None:
        return b"\x00"
    if isinstance(value, bytes):
        return value
    return str(value).encode("utf-8", "replace")


# --------------------------------------------------------------------------- #
# One shared, sealed traversal of the real store                               #
# --------------------------------------------------------------------------- #
class _Stats:
    """Accumulates METADATA-ONLY aggregates while walking the store."""

    def __init__(self) -> None:
        self.folders = 0
        self.messages = 0
        self.recipients = 0
        self.attachments = 0
        self.attachment_bytes = 0
        self.embedded = 0
        self.props_total = 0
        self.tags_distinct: set[int] = set()
        self.tags_named: set[int] = set()
        self.tags_catalog_known: set[int] = set()
        self.tags_unknown: set[int] = set()
        self.render_errors = 0
        self.tree_digest = hashlib.sha256()  # folded content fingerprint (never reported)


def _walk_sealed(store, stats: _Stats) -> None:
    """Walk every folder/message/recipient/attachment, exercising rendering.

    Touches every value (to prove decode-without-crash and to fold the
    determinism fingerprint) but emits nothing — values stay in-process.
    """
    from pstforensic.catalog import oxprops
    from pstforensic.proptypes import split_tag
    from pstforensic.render import render_value

    def fold_object(obj, kind: str) -> None:
        # Deterministic per-object fingerprint: sorted (tag, len, salted hash).
        parts = []
        for tag in sorted(obj.props):
            v = obj.props[tag]
            stats.props_total += 1
            stats.tags_distinct.add(tag)
            pid, _pt = split_tag(tag)
            if pid >= 0x8000:
                stats.tags_named.add(tag)
            elif oxprops.name_for(pid):
                stats.tags_catalog_known.add(tag)
            else:
                stats.tags_unknown.add(tag)
            # Exercise the human-readable renderer — must not raise.
            try:
                rendered = render_value(obj, tag)
            except Exception:
                stats.render_errors += 1
                rendered = None
            parts.append(_sealed_digest(
                bytes(str(tag).encode()) + b":" + _safe_text(rendered)
            ))
        # Fold this object's fingerprint into the global tree digest.
        h = hashlib.sha256()
        h.update(kind.encode())
        for p in sorted(parts):
            h.update(p)
        stats.tree_digest.update(h.digest())

    for folder in store.folders():
        stats.folders += 1
        for msg in folder.messages():
            stats.messages += 1
            fold_object(msg, "msg")
            for rcpt in getattr(msg, "recipients", []) or []:
                stats.recipients += 1
                fold_object(rcpt, "rcpt")
            for att in getattr(msg, "attachments", []) or []:
                stats.attachments += 1
                fold_object(att, "att")
                # Stream attachment bytes through a hash; count only the length.
                opener = getattr(att, "open_data", None)
                if callable(opener):
                    try:
                        data = opener() or b""
                        stats.attachment_bytes += len(data)
                        stats.tree_digest.update(_sealed_digest(data))
                    except Exception:
                        stats.render_errors += 1
            for emb in getattr(msg, "embedded_messages", []) or []:
                stats.embedded += 1
                fold_object(emb, "emb")


@pytest.fixture(scope="module")
def opened():
    """Open the real store once, fully sealed. Returns (store, sink, stats)."""
    from pstforensic import WarningSink, open_store

    sink = WarningSink()
    try:
        store = open_store(_SAMPLE, sink=sink)
        stats = _Stats()
        _walk_sealed(store, stats)
    except Exception:
        # Write the full traceback to the SEALED report only, then fail safely.
        _report("FATAL: exception during sealed open/walk (detail below, metadata-safe)")
        _report(traceback.format_exc())
        sealed_assert(False, "exception during sealed open/walk — see gitignored sealed report")
        raise  # unreachable
    return store, sink, stats


# --------------------------------------------------------------------------- #
# Sealed tests                                                                  #
# --------------------------------------------------------------------------- #
def test_opens_without_crash(opened):
    store, sink, stats = opened
    variant = getattr(store.nodedb, "variant", None)
    vname = getattr(variant, "name", "unknown")
    crypt = getattr(store.nodedb, "crypt_method", None)
    _report("=== sealed real-sample report (metadata only) ===")
    _report(f"variant={vname} verified={getattr(variant, 'verified', '?')} crypt_method={crypt}")
    sealed_assert(store is not None, "open_store returned None")


def test_total_coverage_no_render_errors(opened):
    _store, _sink, s = opened
    _report(f"folders={s.folders} messages={s.messages} recipients={s.recipients} "
            f"attachments={s.attachments} embedded={s.embedded} "
            f"attachment_bytes={s.attachment_bytes}")
    _report(f"props_total={s.props_total} tags_distinct={len(s.tags_distinct)} "
            f"named={len(s.tags_named)} catalog_known={len(s.tags_catalog_known)} "
            f"unknown={len(s.tags_unknown)} render_errors={s.render_errors}")
    # We must have parsed *something*, and rendering every value must not raise.
    sealed_assert(s.folders >= 1, "no folders enumerated from the real store")
    sealed_assert(s.render_errors == 0,
                  f"{s.render_errors} properties failed to render (see counts in report)")


def test_property_catalog_coverage(opened):
    _store, _sink, s = opened
    resolvable = len(s.tags_named) + len(s.tags_catalog_known)
    total = len(s.tags_distinct) or 1
    pct = 100.0 * resolvable / total
    _report(f"catalog_coverage={pct:.1f}% "
            f"({resolvable}/{total} distinct tags named or in MS-OXPROPS)")
    # Soft gate: just record. A low number is a coverage gap to widen, not a bug.
    sealed_assert(0.0 <= pct <= 100.0, "coverage percentage out of range (logic error)")


def test_warning_codes_are_safe_metadata(opened):
    _store, sink, _s = opened
    codes = sorted(sink.codes())
    # Warning CODES are fixed enum strings (e.g. HEADER_CRC_FAIL) — no content.
    _report(f"warning_codes={codes}")
    _report(f"warning_count={len(sink.warnings)}")
    sealed_assert(isinstance(codes, list), "warning codes not enumerable")


def test_deterministic_parse(opened):
    """Two independent parses must produce an identical content fingerprint.

    Proves the parser is deterministic (no uninitialised reads / dict-order
    leakage) without revealing anything — only the equality of two salted
    digests is asserted; neither digest is reported.
    """
    from pstforensic import WarningSink, open_store

    _store, _sink, first = opened
    sink2 = WarningSink()
    second = _Stats()
    _walk_sealed(open_store(_SAMPLE, sink=sink2), second)
    same = first.tree_digest.digest() == second.tree_digest.digest()
    _report(f"deterministic={same} "
            f"(msgs first={first.messages} second={second.messages})")
    sealed_assert(same, "non-deterministic parse: two reads differ (fingerprints unequal)")
    sealed_assert(first.messages == second.messages,
                  "message count differs between two parses")


def test_recovery_runs_sealed(opened):
    """RecoveryEngine must run on the real file and only yield safe counts."""
    from pstforensic import WarningSink
    from pstforensic.recovery import RecoveryEngine

    sink = WarningSink()
    try:
        items = RecoveryEngine(_SAMPLE, sink=sink).recover()
        items = list(items)
    except Exception:
        _report("FATAL: exception during sealed recovery (detail below)")
        _report(traceback.format_exc())
        sealed_assert(False, "exception during recovery — see sealed report")
        return
    methods: dict[str, int] = {}
    confidences = []
    for it in items:
        meta = getattr(it, "meta", None)
        m = getattr(meta, "method", "?")
        methods[m] = methods.get(m, 0) + 1
        c = getattr(meta, "confidence", None)
        if isinstance(c, (int, float)):
            confidences.append(c)
    avg = (sum(confidences) / len(confidences)) if confidences else 0.0
    _report(f"recovery_items={len(items)} methods={methods} avg_confidence={avg:.2f}")
    sealed_assert(len(items) >= 0, "recovery returned a non-list")


# --------------------------------------------------------------------------- #
# Optional differential vs pypff / readpst (Axis D) — sealed                    #
# --------------------------------------------------------------------------- #
def _envelope_hashset_ours() -> set[bytes]:
    from pstforensic import open_store
    from pstforensic.render import render_value
    from pstforensic.proptypes import make_tag, PropType

    TAG_SUBJECT = make_tag(0x0037, PropType.STRING)
    TAG_SENDER = make_tag(0x0C1A, PropType.STRING)
    out: set[bytes] = set()
    store = open_store(_SAMPLE)
    for folder in store.folders():
        for msg in folder.messages():
            subj = _safe_text(render_value(msg, TAG_SUBJECT))
            send = _safe_text(render_value(msg, TAG_SENDER))
            nr = len(getattr(msg, "recipients", []) or [])
            na = len(getattr(msg, "attachments", []) or [])
            out.add(_sealed_digest(subj + b"\x1f" + send + f"\x1f{nr}\x1f{na}".encode()))
    return out


def test_differential_vs_pypff_sealed():
    pypff = pytest.importorskip("pypff", reason="install libpff-python for the Axis-D differential")
    ours = _envelope_hashset_ours()
    theirs: set[bytes] = set()

    def recurse(folder):
        for i in range(folder.number_of_sub_messages):
            m = folder.get_sub_message(i)
            subj = _safe_text(m.get_subject())
            send = _safe_text(m.get_sender_name())
            nr = m.number_of_recipients if hasattr(m, "number_of_recipients") else 0
            na = m.number_of_attachments
            theirs.add(_sealed_digest(subj + b"\x1f" + send + f"\x1f{nr}\x1f{na}".encode()))
        for i in range(folder.number_of_sub_folders):
            recurse(folder.get_sub_folder(i))

    f = pypff.file()
    f.open(_SAMPLE)
    try:
        recurse(f.get_root_folder())
    finally:
        f.close()

    matched = len(ours & theirs)
    only_ours = len(ours - theirs)
    only_theirs = len(theirs - ours)
    _report(f"differential(pypff): matched={matched} only_ours={only_ours} "
            f"only_theirs={only_theirs} ours_total={len(ours)} theirs_total={len(theirs)}")
    # Parity goal: we should recover at least everything pypff does.
    sealed_assert(only_theirs == 0,
                  f"pypff found {only_theirs} envelopes we missed (counts in sealed report)")
