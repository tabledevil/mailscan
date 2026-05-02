"""Markdown renderer with proper escaping and None handling."""

from __future__ import annotations

import re

from renderers import Renderer, ReportNode, _register

# Characters that need escaping in Markdown inline text
_MD_ESCAPE_RE = re.compile(r"([\\`*_\[\]{}()#+\-.!|~>])")

_SEVERITY_BADGE = {
    "CRITICAL": "🟥 **CRITICAL**",
    "HIGH":     "🟧 **HIGH**",
    "MEDIUM":   "🟨 **MEDIUM**",
    "LOW":      "🟦 **LOW**",
    "INFO":     "",  # no badge for INFO — keep output uncluttered
}


def _escape_md(text: str | None) -> str:
    """Escape Markdown special characters in *text*."""
    if text is None:
        return ""
    return _MD_ESCAPE_RE.sub(r"\\\1", str(text))


def _safe(text) -> str:
    """Convert to string, handle None."""
    if text is None:
        return ""
    return str(text)


def _tree_max_severity(node: ReportNode) -> int:
    worst = node.max_severity
    for child in node.children:
        worst = min(worst, _tree_max_severity(child))
    return worst


@_register
class MarkdownRenderer(Renderer):
    format_name = "markdown"

    def _render(self, tree: ReportNode, verbosity: int) -> str:
        lines: list[str] = []
        self._render_node(tree, lines, level=0)
        return "\n".join(lines) + "\n"

    def _render_node(self, node: ReportNode, lines: list[str], level: int):
        indent = "  " * level
        mime = _escape_md(node.info["mime_type"])
        size = node.info["size"]
        sev_int = _tree_max_severity(node)
        sev_name = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFO"}[sev_int]
        sev_tag = ""
        if sev_int <= 2:  # only MEDIUM or worse warrants a header tag
            sev_tag = f"  {_SEVERITY_BADGE[sev_name]}"
        lines.append(f"{indent}* **{mime}** ({size} bytes){sev_tag}")

        info = _escape_md(node.info["analyzer_info"])
        lines.append(f"{indent}  * **Info**: {info}")

        if node.info["filename"]:
            fn = _escape_md(node.info["filename"])
            lines.append(f"{indent}  * **Filename**: {fn}")

        md5 = node.info["md5"]
        lines.append(f"{indent}  * **MD5**: `{md5}`")
        sha1 = node.info.get("sha1")
        sha256 = node.info.get("sha256")
        if sha1:
            lines.append(f"{indent}  * **SHA1**: `{sha1}`")
        if sha256:
            lines.append(f"{indent}  * **SHA256**: `{sha256}`")

        for report in node.reports:
            label = _escape_md(report["label"])
            sev = report.get("severity", "INFO")
            badge = _SEVERITY_BADGE.get(sev, "")
            prefix = f"{badge} " if badge else ""
            if report["content_type"] == "application/x-matt-hops":
                self._render_hop_table(report, lines, indent)
            elif report["content_type"] == "image/png":
                alt = _safe(report["text"]) or "preview in HTML report"
                lines.append(f"{indent}  * {prefix}**{label}**: \\[Image: {_escape_md(alt)}\\]")
            else:
                text = _safe(report["text"])
                # For multi-line content, use a fenced code block
                if "\n" in text:
                    lines.append(f"{indent}  * {prefix}**{label}**:")
                    lines.append(f"{indent}    ```")
                    for tl in text.splitlines():
                        lines.append(f"{indent}    {tl}")
                    lines.append(f"{indent}    ```")
                else:
                    lines.append(f"{indent}  * {prefix}**{label}**: {_escape_md(text)}")

        for child in node.children:
            self._render_node(child, lines, level + 1)

    @staticmethod
    def _render_hop_table(report: dict, lines: list[str], indent: str):
        """Render mail route hops as a Markdown pipe table."""
        hops = report.get("data", {}).get("hops", [])
        if not hops:
            text = _safe(report.get("text", ""))
            lines.append(f"{indent}  * **mail\\_route**: {_escape_md(text)}")
            return

        lines.append(f"{indent}  * **mail\\_route**:")
        lines.append(f"{indent}")
        lines.append(f"{indent}    | # | Server | From | Proto | TLS | Timestamp | Delta |")
        lines.append(f"{indent}    |---|--------|------|-------|-----|-----------|-------|")

        for hop in hops:
            num = hop["hop"]
            by = _escape_md(hop["by_hostname"])
            by_ip = _escape_md(hop.get("by_ip", ""))
            if by_ip and by_ip != by:
                by += f" \\[{by_ip}\\]"

            from_name = _escape_md(hop.get("from_name", "?"))
            from_ip = _escape_md(hop.get("from_ip", ""))
            from_cell = from_name
            if from_ip and from_ip != from_name:
                from_cell += f" \\[{from_ip}\\]"
            ann = hop.get("annotations", [])
            if ann:
                from_cell += f" ({', '.join(ann)})"

            proto = _escape_md(hop.get("protocol", ""))
            tls_val = _escape_md(hop.get("tls") or hop.get("cipher", ""))
            if not tls_val and hop.get("no_tls"):
                tls_val = "NONE"

            ts = _escape_md(hop.get("timestamp", ""))
            if hop.get("tz_changed"):
                ts += f" ({_escape_md(hop.get('prev_tz', ''))} -> {_escape_md(hop.get('tz_offset', ''))})"

            delta_d = _escape_md(hop.get("delta_display", ""))
            delta_s = hop.get("delta_seconds")
            if delta_d:
                if delta_s is not None and delta_s < 0:
                    delta_cell = delta_d
                else:
                    delta_cell = f"+{delta_d}"
            else:
                delta_cell = ""

            lines.append(f"{indent}    | {num} | {by} | {from_cell} | {proto} | {tls_val} | {ts} | {delta_cell} |")

            for inf in hop.get("inferred_after", []):
                inf_label = _escape_md(inf.get("label", ""))
                lines.append(f"{indent}    | ~ | *\\[inferred\\] {inf_label}* | | | | | |")

        # Footer
        if hops:
            last_hop = hops[-1]
            for item in last_hop.get("footer", []):
                lines.append(f"{indent}")
                lines.append(f"{indent}    {_escape_md(item.get('label', ''))}")
