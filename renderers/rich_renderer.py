"""Rich console renderer — styled, coloured tree output.

Uses the ``rich`` library for beautiful terminal output with:
- Tree structure with box-drawing connectors
- Severity-coloured badges on findings
- Monospace hashes
- Structured display for mail route, auth results, IOCs, VBA, summaries
- Color-coded TLS, SPF/DKIM/DMARC, entropy indicators
"""

from __future__ import annotations

import logging
import re
from io import StringIO

from renderers import Renderer, ReportNode, _register

log = logging.getLogger("matt")

try:
    from rich.console import Console, Group
    from rich.panel import Panel
    from rich.text import Text
    from rich.tree import Tree
    from rich.table import Table
    from rich.syntax import Syntax
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

# Auth result colors
_AUTH_COLORS = {
    "pass": "bold green",
    "fail": "bold red",
    "softfail": "bold red",
    "none": "yellow",
    "neutral": "yellow",
    "temperror": "yellow",
    "permerror": "bold red",
}

# Labels that get special rendering treatment
_SUMMARY_LABEL = "summary"
_AUTH_LABEL = "auth"
_IOC_LABEL = "iocs"
_ENTROPY_LABEL = "entropy"
_VBA_PREFIX = "VBA:"


def _is_vba_source(label: str) -> bool:
    return label.startswith(_VBA_PREFIX) or label.startswith("vba_source")


def _is_body_text(report: dict) -> bool:
    """Reports that contain email/document body text (large content, no label or generic label)."""
    label = report.get("label", "")
    text = str(report.get("text", "") or "")
    # Unlabeled reports with multi-line text are usually body content
    if not label and "\n" in text and len(text) > 100:
        return True
    return False


def _is_file_listing(report: dict) -> bool:
    """Reports that list archive contents."""
    text = str(report.get("text", "") or "")
    label = report.get("label", "")
    # Archive listings typically have filenames with sizes in brackets
    if not label and "\n" in text and ("[" in text or text.count("\n") > 2):
        # Check for archive listing patterns: "filename.ext  [size]" or "filename.ext <encrypted>"
        lines = text.strip().split("\n")
        if lines and any(re.search(r'\[[\d,]+\]|\<encrypted\>', line) for line in lines[:5]):
            return True
    return False


def _is_metadata_group(reports: list[dict]) -> list[dict]:
    """Find consecutive single-line INFO reports that form a metadata group (PDF fields, etc.)."""
    # Labels that are typically document metadata
    meta_labels = {"Pages", "title", "subject", "creator", "Author", "producer",
                   "Document type", "Nesting depth", "format", "dimensions",
                   "mode", "Method", "method"}
    return [r for r in reports if r.get("label", "") in meta_labels
            and r.get("severity", "") == "INFO"
            and "\n" not in str(r.get("text", "") or "")]


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

        # File identity panel — hashes, MIME, entropy, fuzzy hashes
        tree.add(self._make_file_identity_panel(node))

        # Reports — with smart grouping
        if node.reports:
            self._render_reports(node.reports, tree)

        # Recurse into children
        for child in node.children:
            self._build_rich_tree(child, tree)

        return tree

    # Labels absorbed into the file identity panel
    _IDENTITY_LABELS = {"entropy", "fuzzy_hash", "exiftool"}

    def _render_reports(self, reports: list[dict], tree: Tree):
        """Render reports with smart dispatch based on label and content type."""
        # Find metadata reports to group together
        meta_reports = _is_metadata_group(reports)
        meta_labels = {r["label"] for r in meta_reports}
        meta_rendered = False

        for report in reports:
            label = report.get("label", "")
            content_type = report.get("content_type", "text/plain")

            # Skip reports absorbed into file identity panel
            if label in self._IDENTITY_LABELS:
                continue

            # Hop-aware mail route
            if content_type == "application/x-matt-hops":
                hop_panel = self._make_hop_panel(report)
                if hop_panel:
                    tree.add(hop_panel)
                continue

            # Email summary → structured table
            if label == _SUMMARY_LABEL:
                tree.add(self._make_summary_panel(report))
                continue

            # Auth results → color-coded badges
            if label == _AUTH_LABEL:
                tree.add(self._make_auth_display(report))
                continue

            # IOC reports → structured display
            if label == _IOC_LABEL:
                tree.add(self._make_ioc_display(report))
                continue

            # Entropy — already in file identity panel
            if label == _ENTROPY_LABEL:
                continue

            # VBA source → code panel
            if _is_vba_source(label):
                tree.add(self._make_vba_panel(report))
                continue

            # Metadata group → consolidated table
            if label in meta_labels:
                if not meta_rendered:
                    meta_rendered = True
                    tree.add(self._make_metadata_table(meta_reports))
                continue

            # Image preview
            if content_type == "image/png":
                tree.add(self._make_report_text(report))
                continue

            # Body text / document content → dimmed panel
            if _is_body_text(report):
                tree.add(self._make_content_panel(report))
                continue

            # File listings → monospaced panel
            if _is_file_listing(report):
                tree.add(self._make_listing_panel(report))
                continue

            # Default: styled text
            tree.add(self._make_report_text(report))

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

    # ------------------------------------------------------------------
    # File identity panel
    # ------------------------------------------------------------------

    @staticmethod
    def _make_file_identity_panel(node: ReportNode):
        """Build a unified file identity panel with hashes, MIME, entropy map."""
        info = node.info

        table = Table(show_header=False, box=None, padding=(0, 1, 0, 0), expand=False)
        table.add_column("key", style="bold cyan", width=12, no_wrap=True)
        table.add_column("value")

        # Analyzer info
        table.add_row("info", str(info.get("analyzer_info") or ""))

        # Filename
        if info.get("filename"):
            table.add_row("filename", str(info["filename"]))

        # File type detection — boxed table with all providers
        type_panel = RichRenderer._make_type_panel(info)
        if type_panel:
            table.add_row("type", type_panel)

        # Hashes
        md5 = info.get("md5", "")
        sha1 = info.get("sha1", "")
        sha256 = info.get("sha256", "")
        if md5:
            table.add_row("md5", Text(md5, style="dim green"))
        if sha1:
            table.add_row("sha1", Text(sha1, style="dim green"))
        if sha256:
            table.add_row("sha256", Text(sha256, style="dim green"))

        # Size
        size = info.get("size", 0)
        if size >= 1024 * 1024:
            size_str = f"{size:,} bytes ({size / (1024*1024):.1f} MB)"
        elif size >= 1024:
            size_str = f"{size:,} bytes ({size / 1024:.1f} KB)"
        else:
            size_str = f"{size:,} bytes"
        table.add_row("size", Text(size_str, style="dim"))

        # Entropy (pulled from reports)
        entropy_report = None
        fuzzy_report = None
        for r in node.reports:
            if r.get("label") == "entropy":
                entropy_report = r
            elif r.get("label") == "fuzzy_hash":
                fuzzy_report = r

        if entropy_report:
            entropy_data = entropy_report.get("data", {})
            entropy_val = entropy_data.get("entropy", 0.0) if isinstance(entropy_data, dict) else 0.0
            if not entropy_val:
                match = re.search(r'([\d.]+)', str(entropy_report.get("text", "")))
                entropy_val = float(match.group(1)) if match else 0.0

            # Overall entropy value and severity
            sev = entropy_report.get("severity", "INFO")

            if entropy_val >= 7.5:
                label_style = "red"
            elif entropy_val >= 6.0:
                label_style = "yellow"
            else:
                label_style = "green"

            ent_text = Text()
            if sev != "INFO":
                sev_style = _SEVERITY_STYLES.get(sev, "dim")
                ent_text.append(f"[{sev}] ", style=sev_style)
            ent_text.append(f"{entropy_val:.2f}/8.0", style=label_style)

            table.add_row("entropy", ent_text)

            # Entropy map — block-wise heatmap
            entropy_map = info.get("entropy_map", [])
            if entropy_map and len(entropy_map) > 1:
                map_text = RichRenderer._render_entropy_map(entropy_map, info.get("size", 0))
                table.add_row("", map_text)

        # Fuzzy hashes
        if fuzzy_report:
            ftext = str(fuzzy_report.get("text", "") or "")
            for line in ftext.strip().split("\n"):
                if ":" in line:
                    fname, _, fval = line.partition(":")
                    table.add_row(fname.strip(), Text(fval.strip(), style="dim green"))

        # Exiftool grouped metadata
        exiftool_report = None
        for r in node.reports:
            if r.get("label") == "exiftool":
                exiftool_report = r
                break
        if exiftool_report and isinstance(exiftool_report.get("data"), dict):
            exiftool_panel = RichRenderer._make_exiftool_panel(exiftool_report)
            if exiftool_panel:
                table.add_row("", exiftool_panel)

        return table

    @staticmethod
    def _make_type_panel(info: dict):
        """Build a boxed table showing all file type provider verdicts, grouped if identical."""
        all_dets = info.get("all_detections", [])
        exiftool_ft = info.get("exiftool_filetype", {})

        # Build list of (provider, mime, description) tuples
        entries = []
        for det in all_dets:
            provider = det.get("provider", "")
            mime = det.get("mime", "")
            desc = det.get("description", "")
            err = det.get("error", "")
            if err:
                entries.append((provider, None, err))
            else:
                entries.append((provider, mime, desc))

        if exiftool_ft.get("mime"):
            ext = exiftool_ft.get("extension", "")
            ft = exiftool_ft.get("filetype", "")
            desc_parts = []
            if ft:
                desc_parts.append(ft)
            if ext:
                desc_parts.append(f".{ext}")
            entries.append(("exiftool", exiftool_ft["mime"], "  ".join(desc_parts)))

        if not entries:
            # Fallback: single detection from magic_info
            mime = info.get("mime_type", "")
            desc = info.get("magic_description", "")
            provider = info.get("magic_provider", "")
            t = Text(mime, style="bold magenta")
            if desc:
                t.append(f"  ({desc})", style="dim")
            if provider:
                t.append(f"  [{provider}]", style="dim italic")
            return t

        # Group entries with identical mime AND description
        grouped: list[list] = []  # [[providers_list, mime, description], ...]
        for provider, mime, desc in entries:
            if mime is None:
                grouped.append([[provider], None, desc])
                continue
            found = False
            for g in grouped:
                if g[1] == mime and g[2] == desc and g[1] is not None:
                    g[0].append(provider)
                    found = True
                    break
            if not found:
                grouped.append([[provider], mime, desc])

        type_table = Table(
            show_header=False, box=box.SIMPLE,
            padding=(0, 1, 0, 0), expand=False,
        )
        type_table.add_column("providers", min_width=14, no_wrap=True)
        type_table.add_column("mime", no_wrap=True)
        type_table.add_column("description")

        for providers, mime, desc in grouped:
            prov_label = ", ".join(providers)
            prov_text = Text(prov_label, style="dim italic")
            if mime is None:
                mime_text = Text("unavailable", style="dim red")
                type_table.add_row(prov_text, mime_text, Text(desc or "", style="dim"))
            else:
                mime_text = Text(mime, style="bold magenta")
                desc_text = Text(desc or "", style="dim")
                type_table.add_row(prov_text, mime_text, desc_text)

        return type_table

    @staticmethod
    def _render_entropy_map(entropy_map: list[float], file_size: int = 0) -> Text:
        """Render a block-wise entropy distribution as a colored heatmap line."""
        # Block characters for granularity (8 levels)
        blocks = " ░▒▓█"
        result = Text()

        for val in entropy_map:
            # Map 0.0-8.0 to block index
            idx = min(int(val / 8.0 * (len(blocks) - 1)), len(blocks) - 1)
            # Color based on entropy
            if val >= 7.5:
                style = "red"
            elif val >= 6.0:
                style = "yellow"
            elif val >= 3.0:
                style = "green"
            else:
                style = "dim"
            result.append(blocks[idx], style=style)

        # Right-side legend: block count × block size
        num_blocks = len(entropy_map)
        if num_blocks and file_size:
            block_size = file_size // num_blocks
            if block_size >= 1024 * 1024:
                bs_str = f"{block_size / (1024 * 1024):.1f}MB"
            elif block_size >= 1024:
                bs_str = f"{block_size / 1024:.1f}KB"
            else:
                bs_str = f"{block_size}B"
            result.append(f"  {num_blocks}\u00d7{bs_str}", style="dim")

        return result

    # ------------------------------------------------------------------
    # Exiftool grouped metadata
    # ------------------------------------------------------------------

    @staticmethod
    def _make_exiftool_panel(report: dict):
        """Render exiftool metadata with each group as a labeled section."""
        data = report.get("data", {})
        if not data or not isinstance(data, dict):
            return None

        inner_table = Table(
            show_header=False, box=None,
            padding=(0, 1, 0, 0), expand=False,
        )
        inner_table.add_column("key", style="dim", width=22, no_wrap=True)
        inner_table.add_column("value")

        has_rows = False
        for group_name, fields in data.items():
            if not fields:
                continue
            # Group header
            inner_table.add_row(
                Text(f"[{group_name}]", style="bold cyan"), Text("")
            )
            for field, value in fields.items():
                val_str = str(value)
                # Truncate very long values
                if len(val_str) > 80:
                    val_str = val_str[:77] + "..."
                inner_table.add_row(f"  {field}", val_str)
                has_rows = True

        if not has_rows:
            return None

        return Panel(
            inner_table, title="[bold]exiftool[/bold]",
            border_style="dim", expand=False,
        )

    # ------------------------------------------------------------------
    # Email summary
    # ------------------------------------------------------------------

    @staticmethod
    def _make_summary_panel(report: dict):
        """Render email summary (From/To/Subject/Date) as a structured table."""
        text = str(report.get("text", "") or "")

        table = Table(
            show_header=False, box=None,
            padding=(0, 1, 0, 0), expand=False,
        )
        table.add_column("field", style="bold", width=9, no_wrap=True)
        table.add_column("value")

        for line in text.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                field, _, value = line.partition(":")
                field = field.strip()
                value = value.strip()
                # Style email addresses
                styled = Text()
                # Highlight email addresses in angle brackets
                parts = re.split(r'(<[^>]+>)', value)
                for part in parts:
                    if part.startswith("<") and part.endswith(">") and "@" in part:
                        styled.append(part, style="cyan")
                    elif "@" in part and " " not in part.strip():
                        styled.append(part, style="cyan")
                    else:
                        styled.append(part)
                table.add_row(field, styled)
            else:
                table.add_row("", line)

        return Panel(table, title="[bold]summary[/bold]", border_style="dim", expand=False)

    # ------------------------------------------------------------------
    # Auth results (SPF/DKIM/DMARC)
    # ------------------------------------------------------------------

    @staticmethod
    def _make_auth_display(report: dict):
        """Render auth results with color-coded pass/fail badges."""
        sev = report.get("severity", "INFO")
        style = _SEVERITY_STYLES.get(sev, "dim")
        text = str(report.get("text", "") or "")

        result = Text()
        if sev != "INFO":
            result.append(f"[{sev}] ", style=style)
        result.append("auth: ", style="bold")

        # Parse individual method results: SPF=pass, DKIM=fail, etc.
        parts = re.split(r',\s*', text)
        for i, part in enumerate(parts):
            if i > 0:
                result.append("  ")
            match = re.match(r'(\w+)=(\w+)(.*)', part)
            if match:
                method = match.group(1)
                value = match.group(2)
                rest = match.group(3)
                color = _AUTH_COLORS.get(value.lower(), "")
                result.append(f"{method}=", style="bold")
                result.append(value, style=color)
                if rest:
                    result.append(rest, style="dim")
            else:
                result.append(part)

        return result

    # ------------------------------------------------------------------
    # IOC display
    # ------------------------------------------------------------------

    @staticmethod
    def _make_ioc_display(report: dict):
        """Render IOCs as a structured, labeled display."""
        sev = report.get("severity", "INFO")
        style = _SEVERITY_STYLES.get(sev, "dim")
        text = str(report.get("text", "") or "")

        result = Text()
        if sev != "INFO":
            result.append(f"[{sev}] ", style=style)
        result.append("iocs: ", style="bold")

        # Parse "Type: value1, value2\nType2: value3" format
        lines = text.strip().split("\n")
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue
            if i > 0:
                result.append("\n      ")
            if ":" in line:
                label_part, _, values_part = line.partition(":")
                result.append(f"{label_part.strip()}: ", style="bold dim")
                # Color IOC values
                for j, val in enumerate(values_part.split(",")):
                    val = val.strip()
                    if j > 0:
                        result.append(", ")
                    result.append(val, style="cyan")
            else:
                result.append(line, style="cyan")

        return result

    # (_make_entropy_display removed — entropy is now in the file identity panel)

    # ------------------------------------------------------------------
    # VBA source code
    # ------------------------------------------------------------------

    @staticmethod
    def _make_vba_panel(report: dict):
        """Render VBA source in a code panel."""
        label = report.get("label", "")
        sev = report.get("severity", "INFO")
        text = str(report.get("text", "") or "")

        # Truncate for console display
        if len(text) > 2000:
            text = text[:1997] + "..."

        try:
            code = Syntax(text, "vb", theme="monokai", line_numbers=False, word_wrap=True)
            title_text = f"[bold]{label}[/bold]"
            if sev != "INFO":
                sev_style = _SEVERITY_STYLES.get(sev, "")
                title_text = f"[{sev_style}][{sev}][/{sev_style}] {title_text}"
            return Panel(code, title=title_text, border_style="dim", expand=False)
        except Exception:
            # Fallback to plain text if Syntax fails
            return RichRenderer._make_report_text(report)

    # ------------------------------------------------------------------
    # Document metadata table
    # ------------------------------------------------------------------

    @staticmethod
    def _make_metadata_table(meta_reports: list[dict]):
        """Consolidate single-value metadata reports into one table."""
        table = Table(
            show_header=False, box=None,
            padding=(0, 1, 0, 0), expand=False,
        )
        table.add_column("key", style="bold", width=12, no_wrap=True)
        table.add_column("value")

        for r in meta_reports:
            label = r.get("label", "")
            text = str(r.get("text", "") or "")
            table.add_row(label, text)

        return Panel(table, title="[bold]metadata[/bold]", border_style="dim", expand=False)

    # ------------------------------------------------------------------
    # Body text / content panel
    # ------------------------------------------------------------------

    @staticmethod
    def _make_content_panel(report: dict):
        """Render body text in a dimmed panel to separate it from findings."""
        text = str(report.get("text", "") or "")
        if len(text) > 1500:
            text = text[:1497] + "..."

        content = Text(text, style="")
        label = report.get("label", "")
        title = f"[bold]{label}[/bold]" if label else "[dim]content[/dim]"
        return Panel(content, title=title, border_style="dim", expand=False)

    # ------------------------------------------------------------------
    # Archive file listing
    # ------------------------------------------------------------------

    @staticmethod
    def _make_listing_panel(report: dict):
        """Render archive file listing in a monospaced panel."""
        text = str(report.get("text", "") or "")

        lines = text.strip().split("\n")
        result = Text()
        for i, line in enumerate(lines):
            if i > 0:
                result.append("\n")
            line = line.strip()
            # Highlight encrypted markers and dangerous extensions
            if "<encrypted>" in line:
                name_part = line.split("<encrypted>")[0].strip()
                result.append(name_part + " ", style="")
                result.append("<encrypted>", style="bold yellow")
                rest = line.split("<encrypted>")[1] if "<encrypted>" in line else ""
                if rest:
                    result.append(rest, style="dim")
            else:
                # Highlight size in brackets
                size_match = re.search(r'\[[\d,]+\]', line)
                if size_match:
                    before = line[:size_match.start()]
                    size = size_match.group()
                    after = line[size_match.end():]
                    # Check for dangerous extensions
                    ext_match = re.search(r'\.(js|exe|bat|cmd|vbs|wsf|hta|scr|pif|com|ps1|jar)\b',
                                          before, re.IGNORECASE)
                    if ext_match:
                        result.append(before, style="bold red")
                    else:
                        result.append(before)
                    result.append(size, style="dim")
                    if after:
                        result.append(after, style="dim")
                else:
                    result.append(line)

        return Panel(result, title="[bold]contents[/bold]", border_style="dim", expand=False)

    # ------------------------------------------------------------------
    # Hop panel (mail route)
    # ------------------------------------------------------------------

    @staticmethod
    def _make_hop_panel(report: dict):
        """Build a Rich Table inside a Panel for hop-as-server display."""
        if not _RICH_AVAILABLE:
            return None

        hops = report.get("data", {}).get("hops", [])
        if not hops:
            return None

        table = Table(
            title="Mail Route",
            box=box.SIMPLE_HEAVY,
            show_lines=True,
            expand=False,
            title_style="bold cyan",
        )
        table.add_column("#", style="bold", width=4, justify="right")
        table.add_column("Server (by)", min_width=20)
        table.add_column("From", min_width=15)
        table.add_column("Proto", width=8)
        table.add_column("TLS", width=12)
        table.add_column("Timestamp", min_width=22)
        table.add_column("Delta", width=10, justify="right")

        for hop in hops:
            num = str(hop["hop"])

            # Server column
            by_text = Text(hop["by_hostname"])
            if hop.get("by_ip") and hop["by_ip"] != hop["by_hostname"]:
                by_text.append(f" [{hop['by_ip']}]", style="dim")
            if hop.get("server_type"):
                by_text.append(f"\n{hop['server_type']}", style="dim italic")

            # From column
            from_text = Text(hop.get("from_name", "?"))
            if hop.get("from_ip") and hop["from_ip"] != hop.get("from_name", ""):
                from_text.append(f" [{hop['from_ip']}]", style="dim")
            ann = hop.get("annotations", [])
            if ann:
                from_text.append(f" ({', '.join(ann)})", style="italic dim")

            # Proto
            proto = hop.get("protocol", "")

            # TLS column with color
            tls_val = hop.get("tls") or hop.get("cipher", "")
            tls_text = Text()
            if tls_val:
                tls_text.append(tls_val, style="green")
            elif hop.get("no_tls"):
                tls_text.append("NONE", style="bold red")

            # Timestamp with tz-shift note
            ts_text = Text(hop.get("timestamp", ""))
            if hop.get("tz_changed"):
                ts_text.append(f"\n{hop['prev_tz']} \u2192 {hop['tz_offset']}", style="yellow")

            # Delta with color coding
            delta_text = Text()
            delta_s = hop.get("delta_seconds")
            delta_d = hop.get("delta_display", "")
            if delta_d:
                if delta_s is not None and delta_s < 0:
                    delta_text.append(delta_d, style="bold red")
                elif delta_s is not None and delta_s > 300:
                    delta_text.append(f"+{delta_d}", style="yellow")
                else:
                    delta_text.append(f"+{delta_d}", style="dim")

            table.add_row(num, by_text, from_text, proto, tls_text, ts_text, delta_text)

            # Inferred hops after this one
            for inf in hop.get("inferred_after", []):
                inf_text = Text()
                inf_text.append("[inferred] ", style="italic dim")
                inf_text.append(inf.get("label", ""), style="italic")
                table.add_row("~", inf_text, "", "", "", "", "", style="dim")

        # Footer items
        footer_items = []
        if hops:
            last_hop = hops[-1]
            for item in last_hop.get("footer", []):
                footer_items.append(item.get("label", ""))

        if footer_items:
            footer_text = Text()
            for fi in footer_items:
                footer_text.append(f"\n{fi}", style="dim")
            panel_content = Group(table, footer_text)
            return Panel(panel_content, title="[bold]mail_route[/bold]", border_style="dim")

        return Panel(table, title="[bold]mail_route[/bold]", border_style="dim")

    # ------------------------------------------------------------------
    # Default report text
    # ------------------------------------------------------------------

    @staticmethod
    def _make_report_text(report: dict) -> Text:
        """Format a single report entry."""
        sev = report["severity"]
        style = _SEVERITY_STYLES.get(sev, "dim")

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
