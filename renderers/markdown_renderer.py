"""Markdown renderer with proper escaping and None handling."""

from __future__ import annotations

import re

from renderers import Renderer, ReportNode, _register

# Characters that need escaping in Markdown inline text
_MD_ESCAPE_RE = re.compile(r"([\\`*_\[\]{}()#+\-.!|~>])")


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
        lines.append(f"{indent}* **{mime}** ({size} bytes)")

        info = _escape_md(node.info["analyzer_info"])
        lines.append(f"{indent}  * **Info**: {info}")

        if node.info["filename"]:
            fn = _escape_md(node.info["filename"])
            lines.append(f"{indent}  * **Filename**: {fn}")

        md5 = node.info["md5"]
        lines.append(f"{indent}  * **MD5**: `{md5}`")

        for report in node.reports:
            label = _escape_md(report["label"])
            if report["content_type"] == "image/png":
                alt = _safe(report["text"]) or "preview in HTML report"
                lines.append(f"{indent}  * **{label}**: \\[Image: {_escape_md(alt)}\\]")
            else:
                text = _safe(report["text"])
                # For multi-line content, use a fenced code block
                if "\n" in text:
                    lines.append(f"{indent}  * **{label}**:")
                    lines.append(f"{indent}    ```")
                    for tl in text.splitlines():
                        lines.append(f"{indent}    {tl}")
                    lines.append(f"{indent}    ```")
                else:
                    lines.append(f"{indent}  * **{label}**: {_escape_md(text)}")

        for child in node.children:
            self._render_node(child, lines, level + 1)
