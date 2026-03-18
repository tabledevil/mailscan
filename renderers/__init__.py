"""Pluggable report renderer package for MATT.

Usage::

    from renderers import get_renderer
    renderer = get_renderer("rich")   # or "text", "json", "markdown", "html"
    output = renderer.render(structure_root, verbosity=0)
"""

from __future__ import annotations

__all__ = ["Renderer", "get_renderer", "available_formats"]

import abc
import logging
from typing import TYPE_CHECKING

from Utils.advanced_analysis import collect_timeline_events, enrich_iocs
from Utils.ioc_extractor import merge_ioc_dicts, defang_ioc_data
from Config.config import flags

if TYPE_CHECKING:
    from structure import Structure

log = logging.getLogger("matt")


# ------------------------------------------------------------------
# Report-tree node (format-agnostic)
# ------------------------------------------------------------------


class ReportNode:
    """Intermediate representation of one Structure node's analysis results.

    Built once by the base ``Renderer`` and consumed by every subclass so
    the tree-walking / filtering logic is never duplicated.
    """

    __slots__ = ("info", "reports", "children", "max_severity")

    def __init__(self, info: dict, reports: list[dict], children: list["ReportNode"]):
        self.info = info
        self.reports = reports
        self.children = children
        # Highest (= lowest int) severity among own reports
        if reports:
            self.max_severity = min(r["severity_value"] for r in reports)
        else:
            self.max_severity = 4  # INFO


# ------------------------------------------------------------------
# Abstract base renderer
# ------------------------------------------------------------------


class Renderer(abc.ABC):
    """Base class for all MATT output renderers."""

    # Subclasses set this — used by the registry
    format_name: str = ""

    def render(self, root: "Structure", verbosity: int = 0) -> str:
        """Public entry point: build report tree, then format it."""
        self._ioc_summary = self._collect_ioc_summary(root)
        self._timeline = collect_timeline_events(root)
        tree = self._build_tree(root, verbosity)
        return self._render(tree, verbosity)

    @abc.abstractmethod
    def _render(self, tree: ReportNode, verbosity: int) -> str:
        """Subclasses implement this to produce the final string."""
        ...

    # ------------------------------------------------------------------
    # Shared tree-building logic (migrated from reporting.py)
    # ------------------------------------------------------------------

    def _build_tree(self, struct: "Structure", verbosity: int) -> ReportNode:
        info = {
            "index": struct.index,
            "mime_type": struct.mime_type,
            "size": struct.size,
            "filename": struct.filename if struct.has_filename else None,
            "md5": struct.md5,
            "analyzer_name": type(struct.analyzer).__name__,
            "analyzer_info": struct.analyzer.info,
        }

        # Gather reports that pass the verbosity filter
        raw_reports = [r for r in struct.analyzer.summary if r.verbosity <= verbosity]

        # Apply the 'replaces' logic: if report A replaces label B and both
        # are present at this verbosity, suppress B.
        replaced_labels: set[str] = set()
        for r in raw_reports:
            if r.replaces:
                replaced_labels.add(r.replaces)

        filtered = [r for r in raw_reports if r.label not in replaced_labels]

        reports = []
        for r in filtered:
            reports.append(
                {
                    "text": r.text,
                    "short": r.short,
                    "label": r.label or "",
                    "severity": r.severity.name,
                    "severity_value": int(r.severity),
                    "order": r.order,
                    "content_type": r.content_type,
                    "data": r.data,
                }
            )

        children = [
            self._build_tree(child, verbosity) for child in struct.get_children()
        ]

        return ReportNode(info, reports, children)

    # ------------------------------------------------------------------
    # IOC summary collection
    # ------------------------------------------------------------------

    def _collect_ioc_summary(self, root):
        """Walk the struct tree, collect all 'iocs' reports, merge, and enrich."""
        ioc_dicts = []

        def walk(struct):
            for report in struct.analyzer.summary:
                if report.label == "iocs" and isinstance(report.data, dict):
                    ioc_dicts.append(report.data)
            for child in struct.get_children():
                walk(child)

        walk(root)
        if not ioc_dicts:
            return None
        summary = merge_ioc_dicts(ioc_dicts).to_dict()
        summary["passwords"] = []
        has_findings = any(values for key, values in summary.items() if key != "passwords")
        if not has_findings:
            return None
        if flags.defang:
            summary = defang_ioc_data(summary)
            summary["passwords"] = []
        summary["enrichment"] = enrich_iocs(summary)
        return summary

    def format_ioc_summary_lines(self):
        """Return formatted lines for the IOC summary section."""
        if not self._ioc_summary:
            return []
        data = self._ioc_summary
        ip_values = data.get("ipv4", []) + data.get("ipv6", [])
        sections = [
            ("IPs", ip_values), ("Domains", data.get("domains", [])),
            ("URLs", data.get("urls", [])), ("Emails", data.get("emails", [])),
            ("MD5", data.get("md5", [])), ("SHA1", data.get("sha1", [])),
            ("SHA256", data.get("sha256", [])),
        ]
        lines = ["=== IOC SUMMARY ==="]
        for label, values in sections:
            if values:
                lines.append(f"{label:<7}: {', '.join(values)}")
        enrichment = data.get("enrichment", {})
        if enrichment:
            lines.append("")
            lines.append("--- VT Enrichment ---")
            for ioc_value, vt in enrichment.items():
                hits = vt.get("malicious", 0) + vt.get("suspicious", 0)
                if hits > 0:
                    lines.append(f"  {ioc_value}: {hits} hit(s) (malicious={vt['malicious']}, suspicious={vt['suspicious']})")
                else:
                    lines.append(f"  {ioc_value}: clean")
        return lines


# ------------------------------------------------------------------
# Renderer registry
# ------------------------------------------------------------------

_registry: dict[str, type[Renderer]] = {}


def _register(cls: type[Renderer]) -> type[Renderer]:
    """Decorator that registers a renderer subclass."""
    if cls.format_name:
        _registry[cls.format_name] = cls
    return cls


def get_renderer(format_name: str) -> Renderer:
    """Return an instance of the renderer for *format_name*.

    Raises ``ValueError`` if the format is unknown.
    """
    # Lazy-import all renderer modules so they self-register
    _ensure_loaded()

    if format_name not in _registry:
        available = ", ".join(sorted(_registry))
        raise ValueError(
            f"Unknown output format {format_name!r}. Available: {available}"
        )
    return _registry[format_name]()


def available_formats() -> list[str]:
    """Return sorted list of registered format names."""
    _ensure_loaded()
    return sorted(_registry)


_loaded = False


def _ensure_loaded():
    global _loaded
    if _loaded:
        return
    _loaded = True
    # Import submodules so their @_register decorators run
    from renderers import text_renderer  # noqa: F401
    from renderers import rich_renderer  # noqa: F401
    from renderers import json_renderer  # noqa: F401
    from renderers import markdown_renderer  # noqa: F401
    from renderers import html_renderer  # noqa: F401
    from renderers import timeline_renderer  # noqa: F401
