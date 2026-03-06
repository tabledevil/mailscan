"""Rich console renderer — styled, coloured tree output.

Uses the ``rich`` library for beautiful terminal output with:
- Tree structure with box-drawing connectors
- Severity-coloured badges on findings
- Monospace hashes
- Proper text wrapping
"""

from __future__ import annotations

import logging
from io import StringIO

from renderers import Renderer, ReportNode, _register

log = logging.getLogger("matt")

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.tree import Tree
    from rich.table import Table
    from rich import box

    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False

# Map severity names to Rich style markup colours
_SEVERITY_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "bold yellow",
    "LOW": "bold blue",
    "INFO": "dim",
}

_SEVERITY_ICONS = {
    "CRITICAL": "\u2622 ",  # radioactive
    "HIGH": "\u26a0 ",  # warning
    "MEDIUM": "\u25cf ",  # filled circle
    "LOW": "\u2139 ",  # info
    "INFO": "  ",
}


@_register
class RichRenderer(Renderer):
    format_name = "rich"

    def _render(self, tree: ReportNode, verbosity: int) -> str:
        if not _RICH_AVAILABLE:
            log.warning(
                "rich is not installed — falling back to plain text. "
                "Install with: pip install rich"
            )
            from renderers.text_renderer import TextRenderer

            return TextRenderer()._render(tree, verbosity)

        console = Console(file=StringIO(), width=120, force_terminal=True)
        rich_tree = self._build_rich_tree(tree)
        console.print(rich_tree)
        return console.file.getvalue()

    def _build_rich_tree(
        self, node: ReportNode, parent_tree: Tree | None = None
    ) -> Tree:
        """Recursively build a Rich Tree from the ReportNode tree."""
        # Node label
        label = self._make_node_label(node)

        if parent_tree is None:
            tree = Tree(label)
        else:
            tree = parent_tree.add(label)

        # Metadata table (compact, no borders)
        meta = Table(show_header=False, box=None, padding=(0, 1, 0, 0), expand=False)
        meta.add_column("key", style="bold cyan", width=12, no_wrap=True)
        meta.add_column("value")

        meta.add_row("info", str(node.info["analyzer_info"] or ""))
        if node.info["filename"]:
            meta.add_row("filename", str(node.info["filename"]))
        meta.add_row("md5", Text(str(node.info["md5"] or ""), style="dim green"))

        tree.add(meta)

        # Reports
        if node.reports:
            for report in node.reports:
                tree.add(self._make_report_text(report))

        # Recurse into children
        for child in node.children:
            self._build_rich_tree(child, tree)

        return tree

    @staticmethod
    def _make_node_label(node: ReportNode) -> Text:
        """Create the header line for a tree node."""
        t = Text()
        t.append(str(node.info["index"]), style="bold white")
        t.append(" \u00bb ", style="dim")
        t.append(str(node.info["mime_type"] or "unknown"), style="bold magenta")
        t.append(f"  ({node.info['size']} bytes)", style="dim")

        # If there are critical/high findings, add a visual indicator
        if node.max_severity <= 1:  # CRITICAL or HIGH
            sev_name = "CRITICAL" if node.max_severity == 0 else "HIGH"
            style = _SEVERITY_STYLES[sev_name]
            icon = _SEVERITY_ICONS[sev_name]
            t.append(f"  {icon}{sev_name}", style=style)

        return t

    @staticmethod
    def _make_report_text(report: dict) -> Text:
        """Format a single report entry."""
        sev = report["severity"]
        style = _SEVERITY_STYLES.get(sev, "dim")
        icon = _SEVERITY_ICONS.get(sev, "  ")

        t = Text()

        # Severity badge (only for findings, not INFO)
        if sev != "INFO":
            t.append(f"[{sev}]", style=style)
            t.append(" ")

        # Label
        label = report["label"]
        if label:
            t.append(f"{label}: ", style="bold")

        # Content
        if report["content_type"] == "image/png":
            t.append("[Image: preview in HTML report]", style="italic dim")
        else:
            text = str(report["text"]) if report["text"] is not None else ""
            # Truncate very long text for console display
            if len(text) > 500:
                text = text[:497] + "..."
            t.append(text)

        return t
