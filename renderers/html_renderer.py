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

            if report["content_type"] == "image/png" and report.get("data"):
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
