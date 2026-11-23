"""PST/OST analyzer — native, recovery-first, via ``pstforensic``.

Reads healthy and damaged Outlook stores (ANSI/Unicode PST, Unicode and 4K
OST) as tolerantly as Kernel PST Viewer, and reports what the store holds:

  * ``summary``           — format, folders, items by state
  * ``store_integrity``   — header / B-tree / scan findings
  * ``recovered_items``   — deleted, superseded, carved, orphaned, lost items
  * ``damaged_items``     — live items read through damage, with findings

Each item becomes a ``message/rfc822`` child (``pstforensic.export``) so the
rest of MATT (EmailAnalyzer header/route/auth checks, IOC extraction,
attachment analyzers) runs over it: always for recovered items, for live
items up to ``flags.pst_max_live_messages`` (``--pst-max-messages``, 0 = all).
"""
from __future__ import annotations

import logging
from collections import Counter

from structure import Analyzer, Report, Severity

log = logging.getLogger("matt")

PST_MAGIC = b"!BDN"
_OLE_MAGIC = b"\xd0\xcf\x11\xe0"
MAX_LIVE_MESSAGES = 200        # live messages whose bodies/attachments become children
MAX_LISTED = 100               # items listed in a report's text (all are in .data)
_RECOVERED_STATES = ("deleted", "superseded", "carved", "lost", "orphan", "soft_deleted")
_SEVERE_STORE_CODES = {"HEADER_UNUSABLE", "PAGE_UNREADABLE", "SCAN_INCOMPLETE",
                       "VARIANT_FROM_EVIDENCE", "CRYPT_METHOD_UNKNOWN"}


def _cache_dir():
    """pstforensic's structural index cache under MATT's ``--cache-path`` (if
    set), else ``$PSTFORENSIC_CACHE_DIR``, else off."""
    import os
    from Config.config import flags
    if flags.cache_path:
        return os.path.join(os.path.expanduser(flags.cache_path), "pstforensic")
    return None


def _text(value) -> str:
    return "" if value is None else str(value)


def _item_line(item) -> str:
    m = item.message
    when = m.render(0x0E06) or m.render(0x0039) if m is not None else None
    sender = (m.render(0x0C1A) or m.render(0x0C1F)) if m is not None else None
    codes = ",".join(sorted(item.integrity.codes))
    return (f"[{item.state}/{item.provenance}] {_text(item.folder_path) or '-'} | "
            f"{_text(when)} | {_text(sender)} | {_text(item.subject)!r}"
            + (f" | {codes}" if codes else ""))


def _item_data(item) -> dict:
    m = item.message
    d = {
        "state": item.state,
        "provenance": item.provenance,
        "nid": item.nid,
        "folder": item.folder_path,
        "subject": item.subject,
        "findings": sorted(item.integrity.codes),
        "level": item.integrity.level,
    }
    if m is not None:
        d["message_class"] = m.render(0x001A)
        d["sender"] = m.render(0x0C1A) or m.render(0x0C1F)
        d["sent"] = _text(m.render(0x0039)) or None
        d["delivered"] = _text(m.render(0x0E06)) or None
        d["attachments"] = len(m.attachments)
    if item.deletion is not None:
        di = item.deletion
        d["deletion"] = {"kind": di.kind, "original_folder": di.original_folder,
                         "deleted_on": _text(di.deleted_on) or None,
                         "deleted_on_source": di.deleted_on_source,
                         "not_before": _text(di.not_before) or None,
                         "not_before_source": di.not_before_source,
                         "modifier": di.modifier}
    if item.history:
        d["history"] = [{"kind": h.kind, "folder": h.folder_path} for h in item.history]
    if item.supersedes:
        d["supersedes"] = item.supersedes
    return d


class PstAnalyzer(Analyzer):
    compatible_mime_types = ["application/vnd.ms-outlook-pst",
                             "application/x-outlook-pst"]
    description = "PST/OST Mail Store Analyzer (pstforensic)"
    specificity = 21   # PST and MSG share application/vnd.ms-outlook; beat MsgAnalyzer
    optional_pip_dependencies = [("numpy", "numpy")]
    extra = "pst"

    @classmethod
    def can_handle(cls, struct) -> bool:
        data = struct.rawdata
        if not data:
            return False
        if data[:4] == PST_MAGIC:
            return True
        # A store whose header is wiped has no magic: trust the extension,
        # unless the bytes are an OLE/MSG file.
        name = (getattr(struct, "_Structure__filename", None) or "").lower()
        return name.endswith((".pst", ".ost", ".nst")) and data[:4] != _OLE_MAGIC

    @classmethod
    def can_analyze(cls, struct) -> bool:
        # The shared Outlook MIME type (application/vnd.ms-outlook) also covers
        # MSG files, so it is deliberately not in compatible_mime_types.
        return struct.mime_type in cls.compatible_mime_types or cls.can_handle(struct)

    def analysis(self) -> None:
        super().analysis()
        try:
            from pstforensic import open_store
        except ImportError as exc:  # pragma: no cover - package ships with MATT
            log.warning(f"pstforensic unavailable: {exc}")
            return
        try:
            # A large root file arrives memory-mapped; FileReader uses the
            # mapping directly (no copy).
            store = open_store(self.struct.rawdata, cache_dir=_cache_dir())
        except Exception as exc:
            self.reports["pst_error"] = Report(
                f"Not readable as PST/OST: {exc}", label="pst_error",
                severity=Severity.LOW)
            return

        states: Counter = Counter()
        recovered, damaged = [], []
        live_children = 0
        child_idx = 0
        from Config.config import flags
        max_live = getattr(flags, "pst_max_live_messages", MAX_LIVE_MESSAGES)
        for item in store.iter_items():
            states[item.state] += 1
            if item.state in _RECOVERED_STATES:
                recovered.append(item)
            elif item.state == "live_damaged":
                damaged.append(item)
            emit = item.state != "live" or not max_live or live_children < max_live
            if emit and item.message is not None:
                if item.state in ("live", "live_damaged"):
                    live_children += 1
                child_idx = self._emit_children(item, child_idx)

        hdr = store.nodedb.header
        folders = sum(1 for _ in store.folders())
        self.info = f"{store.display_name or 'Outlook store'} ({store.variant.name})"
        lines = [
            f"Store   : {store.display_name!r} ({store.variant.name}, wVer {hdr.wver}, "
            f"crypt {hdr.crypt_method})",
            f"Folders : {folders}",
            "Items   : " + ", ".join(f"{k}={v}" for k, v in sorted(states.items())),
        ]
        if store.has_password:
            lines.append("Password: set (bypassed; read access needs none)")
        if max_live and states.get("live", 0) + states.get("live_damaged", 0) > max_live:
            lines.append(f"Children: the first {max_live} live messages and every "
                         "recovered item (--pst-max-messages 0 for all)")
        self.reports["summary"] = Report("\n".join(lines), label="summary",
                                         data={"states": dict(states), "folders": folders,
                                               "variant": store.variant.name})

        diag = store.diagnostics()
        failures = diag.get("failures") or []
        self.reports["pst_diagnostics"] = Report(
            "Parser diagnostics: "
            + (", ".join(f"{f['phase']}:{f['exception']}×{f['count']} @ {f['location']}"
                         for f in failures[:10]) or "no parser failures")
            + f" | reasons={diag.get('reasons')} | timings={diag.get('timings_s')}",
            short=f"{sum(f['count'] for f in failures)} parser failure(s)",
            label="pst_diagnostics",
            severity=Severity.LOW if failures else Severity.INFO,
            verbosity=0 if failures else 2, data=diag)

        codes = Counter(f.code for f in store.integrity.findings)
        if codes:
            sev = Severity.HIGH if set(codes) & _SEVERE_STORE_CODES else Severity.MEDIUM
            self.reports["store_integrity"] = Report(
                "Store damage read through: " + ", ".join(
                    f"{c}×{n}" for c, n in sorted(codes.items())),
                short="Store damaged", label="store_integrity", severity=sev,
                data=[str(f) for f in store.integrity.findings])

        if recovered:
            self.reports["recovered_items"] = Report(
                f"{len(recovered)} item(s) beyond the live folder tree "
                f"({', '.join(f'{s}={n}' for s, n in sorted(Counter(i.state for i in recovered).items()))}):\n"
                + "\n".join(_item_line(i) for i in recovered[:MAX_LISTED])
                + (f"\n… {len(recovered) - MAX_LISTED} more" if len(recovered) > MAX_LISTED else ""),
                short=f"{len(recovered)} recovered item(s)", label="recovered_items",
                severity=Severity.MEDIUM, data=[_item_data(i) for i in recovered])

        if damaged:
            self.reports["damaged_items"] = Report(
                f"{len(damaged)} live item(s) read through damage:\n"
                + "\n".join(_item_line(i) for i in damaged[:MAX_LISTED]),
                short=f"{len(damaged)} damaged item(s)", label="damaged_items",
                severity=Severity.LOW, data=[_item_data(i) for i in damaged])

    def _emit_children(self, item, idx: int) -> int:
        """One ``message/rfc822`` child per item (``pstforensic.export``):
        original transport headers, bodies, attachments and embedded
        messages, plus ``X-MATT-PST-*`` folder/state/provenance/findings
        headers — so EmailAnalyzer runs its header, route and auth checks
        on PST mail exactly as on .eml files."""
        from pstforensic.export import item_to_eml
        try:
            raw = item_to_eml(item)
        except Exception as exc:
            log.debug(f"PST item → EML failed: {exc}")
            return idx
        if not raw:
            return idx
        prefix = "" if item.state in ("live", "live_damaged") else f"{item.state}_"
        meta = {"pst_state": item.state, "pst_provenance": item.provenance,
                "pst_folder": item.folder_path, "pst_subject": item.subject}
        try:
            self.childitems.append(self.generate_struct(
                data=raw, filename=f"{prefix}message_{idx}.eml",
                mime_type="message/rfc822", index=idx, metadata=meta))
        except Exception as exc:   # one bad child never stops the store
            log.warning(f"PST item {idx} not analyzed: {type(exc).__name__}: {exc}")
            return idx
        return idx + 1
