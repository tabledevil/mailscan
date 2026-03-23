"""HTML report renderer.

Produces a self-contained HTML document with:
- Styled tree view of analysis results
- Severity colour coding
- Safe rendering of embedded email HTML (sandboxed iframe, future)
- Tracking pixel neutralization and link defanging (future)

For now this is a clean rewrite of the old reporting.py HTML output.
The safe-email-preview / justhtml integration is Phase B4 and will be
added once HTMLAnalyzer is rewritten.
"""

from __future__ import annotations

import html

from renderers import Renderer, ReportNode, _register

_SEVERITY_COLOURS = {
    "CRITICAL": "#d32f2f",
    "HIGH": "#e64a19",
    "MEDIUM": "#f9a825",
    "LOW": "#1976d2",
    "INFO": "#757575",
}

_CSS = """\
:root { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; font-size: 14px; }
body { margin: 2em; background: #fafafa; color: #212121; }
h1 { font-size: 1.4em; border-bottom: 2px solid #1976d2; padding-bottom: 0.3em; }
.node { margin-left: 1.5em; border-left: 2px solid #e0e0e0; padding-left: 1em; margin-bottom: 0.8em; }
.node-header { font-weight: 600; font-size: 0.95em; margin-bottom: 0.3em; }
.meta { color: #616161; font-size: 0.85em; }
.meta span { margin-right: 1.2em; }
.md5 { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85em; color: #424242; }
.report { margin: 0.3em 0; font-size: 0.9em; }
.report-label { font-weight: 600; }
.severity-badge { display: inline-block; padding: 0 0.4em; border-radius: 3px; font-size: 0.75em;
                  font-weight: 700; color: #fff; margin-right: 0.4em; vertical-align: middle; }
.report-text { white-space: pre-wrap; word-break: break-word; }
img.preview { max-width: 600px; max-height: 400px; border: 1px solid #bdbdbd; margin-top: 0.3em; }
.hop-table { border-collapse: collapse; width: 100%; font-size: 0.85em; margin: 0.5em 0; }
.hop-table th { background: #e3f2fd; padding: 0.4em 0.6em; text-align: left; border-bottom: 2px solid #1976d2; }
.hop-table td { padding: 0.4em 0.6em; border-bottom: 1px solid #e0e0e0; vertical-align: top; }
.hop-table tr:hover { background: #f5f5f5; }
.hop-inferred { background: #fff3e0; font-style: italic; color: #795548; }
.tls-yes { color: #2e7d32; font-weight: 600; }
.tls-no { color: #c62828; font-weight: 700; }
.delta-neg { color: #c62828; font-weight: 700; }
.delta-high { color: #f9a825; }
.hop-footer { font-size: 0.85em; color: #616161; padding: 0.3em 0.6em; }
"""


@_register
class HtmlRenderer(Renderer):
    format_name = "html"

    def _render(self, tree: ReportNode, verbosity: int) -> str:
        parts: list[str] = []
        parts.append("<!DOCTYPE html>")
        parts.append('<html lang="en"><head><meta charset="utf-8">')
        parts.append("<title>MATT Analysis Report</title>")
        parts.append(f"<style>{_CSS}</style>")
        parts.append("</head><body>")
        parts.append("<h1>MATT Analysis Report</h1>")
        self._render_node(tree, parts, root=True)
        parts.append("</body></html>")
        return "\n".join(parts)

    def _render_node(self, node: ReportNode, parts: list[str], root: bool = False):
        cls = "node" if not root else "node" + " root"
        parts.append(f'<div class="{cls}">')

        mime = html.escape(str(node.info["mime_type"] or ""))
        size = node.info["size"]
        idx = html.escape(str(node.info["index"]))
        parts.append(
            f'<div class="node-header">{idx} &raquo; {mime} '
            f'<span class="meta">({size} bytes)</span></div>'
        )

        info = html.escape(str(node.info["analyzer_info"] or ""))
        parts.append(f'<div class="meta"><span>Analyzer: {info}</span></div>')

        if node.info["filename"]:
            fn = html.escape(str(node.info["filename"]))
            parts.append(f'<div class="meta"><span>Filename: {fn}</span></div>')

        md5 = html.escape(str(node.info["md5"] or ""))
        parts.append(f'<div class="meta"><span class="md5">MD5: {md5}</span></div>')

        for report in node.reports:
            sev = report["severity"]
            colour = _SEVERITY_COLOURS.get(sev, "#757575")
            badge = (
                f'<span class="severity-badge" style="background:{colour}">'
                f"{html.escape(sev)}</span>"
            )
            label = html.escape(report["label"])

            if report["content_type"] == "application/x-matt-hops":
                self._render_hop_table(report, parts)
            elif report["content_type"] == "image/png" and report.get("data"):
                parts.append(
                    f'<div class="report">{badge}'
                    f'<span class="report-label">{label}</span>: '
                    f'<br><img class="preview" '
                    f'src="data:image/png;base64,{report["data"]}" '
                    f'alt="{html.escape(str(report["text"] or ""))}">'
                    f"</div>"
                )
            else:
                text = html.escape(
                    str(report["text"]) if report["text"] is not None else ""
                )
                parts.append(
                    f'<div class="report">{badge}'
                    f'<span class="report-label">{label}</span>: '
                    f'<span class="report-text">{text}</span></div>'
                )

        for child in node.children:
            self._render_node(child, parts)

        parts.append("</div>")

    @staticmethod
    def _render_hop_table(report: dict, parts: list[str]):
        """Render mail route hops as an HTML table."""
        hops = report.get("data", {}).get("hops", [])
        if not hops:
            text = html.escape(str(report.get("text", "")))
            parts.append(f'<div class="report"><span class="report-label">mail_route</span>: '
                         f'<span class="report-text">{text}</span></div>')
            return

        parts.append('<div class="report"><span class="report-label">mail_route</span>')
        parts.append('<table class="hop-table">')
        parts.append('<tr><th>#</th><th>Server (by)</th><th>From</th>'
                     '<th>Proto</th><th>TLS</th><th>Timestamp</th><th>Delta</th></tr>')

        for hop in hops:
            num = hop["hop"]

            # Server
            by = html.escape(hop["by_hostname"])
            by_ip = html.escape(hop.get("by_ip", ""))
            by_cell = by
            if by_ip and by_ip != by:
                by_cell += f' <span style="color:#757575">[{by_ip}]</span>'
            srv = html.escape(hop.get("server_type", ""))
            if srv:
                by_cell += f'<br><span style="color:#757575;font-style:italic">{srv}</span>'

            # From
            from_name = html.escape(hop.get("from_name", "?"))
            from_ip = html.escape(hop.get("from_ip", ""))
            from_cell = from_name
            if from_ip and from_ip != from_name:
                from_cell += f' <span style="color:#757575">[{from_ip}]</span>'
            ann = hop.get("annotations", [])
            if ann:
                from_cell += f' <span style="color:#757575;font-style:italic">({", ".join(html.escape(a) for a in ann)})</span>'

            # TLS
            tls_val = html.escape(hop.get("tls") or hop.get("cipher", ""))
            if tls_val:
                tls_cell = f'<span class="tls-yes">{tls_val}</span>'
            elif hop.get("no_tls"):
                tls_cell = '<span class="tls-no">NONE</span>'
            else:
                tls_cell = ""

            # Timestamp
            ts = html.escape(hop.get("timestamp", ""))
            ts_cell = ts
            if hop.get("tz_changed"):
                prev = html.escape(hop.get("prev_tz", ""))
                cur = html.escape(hop.get("tz_offset", ""))
                ts_cell += f'<br><span style="color:#f9a825">{prev} &rarr; {cur}</span>'

            # Delta
            delta_s = hop.get("delta_seconds")
            delta_d = html.escape(hop.get("delta_display", ""))
            if delta_d:
                if delta_s is not None and delta_s < 0:
                    delta_cell = f'<span class="delta-neg">{delta_d}</span>'
                elif delta_s is not None and delta_s > 300:
                    delta_cell = f'<span class="delta-high">+{delta_d}</span>'
                else:
                    delta_cell = f'+{delta_d}'
            else:
                delta_cell = ""

            parts.append(f'<tr><td>{num}</td><td>{by_cell}</td><td>{from_cell}</td>'
                         f'<td>{html.escape(hop.get("protocol", ""))}</td>'
                         f'<td>{tls_cell}</td><td>{ts_cell}</td><td>{delta_cell}</td></tr>')

            # Inferred hops
            for inf in hop.get("inferred_after", []):
                inf_label = html.escape(inf.get("label", ""))
                parts.append(f'<tr class="hop-inferred"><td>~</td>'
                             f'<td colspan="6">[inferred] {inf_label}</td></tr>')

        parts.append('</table>')

        # Footer
        if hops:
            last_hop = hops[-1]
            for item in last_hop.get("footer", []):
                parts.append(f'<div class="hop-footer">{html.escape(item.get("label", ""))}</div>')

        parts.append('</div>')
