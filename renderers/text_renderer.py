"""Plain-text renderer (no ANSI colours).

Produces the same tree-style output as the old ``reporting.py`` text renderer,
but built on the new ``Renderer`` base class.
"""

from __future__ import annotations

import textwrap

from renderers import Renderer, ReportNode, _register


@_register
class TextRenderer(Renderer):
    format_name = "text"

    def _render(self, tree: ReportNode, verbosity: int) -> str:
        return "".join(self._render_root(tree))

    # ------------------------------------------------------------------
    # Root node (no tree-drawing prefix)
    # ------------------------------------------------------------------

    def _render_root(self, node: ReportNode):
        yield f"{node.info['index']} >> {node.info['mime_type']} {node.info['size']}\n"
        yield f"info     : {node.info['analyzer_info']}\n"
        if node.info["filename"]:
            yield f"filename : {node.info['filename']}\n"
        yield f"md5      : {node.info['md5']}\n"

        yield from self._render_reports(node.reports, prefix="")

        num = len(node.children)
        for i, child in enumerate(node.children):
            yield from self._render_child(child, prefix="", is_last=(i == num - 1))

    # ------------------------------------------------------------------
    # Child nodes (with box-drawing connectors)
    # ------------------------------------------------------------------

    def _render_child(self, node: ReportNode, prefix: str, is_last: bool):
        connector = "\u2514\u2500\u2500 " if is_last else "\u251c\u2500\u2500 "
        yield (
            f"{prefix}{connector}"
            f"{node.info['index']} >> {node.info['mime_type']} {node.info['size']}\n"
        )

        pad = prefix + ("    " if is_last else "\u2502   ")

        yield f"{pad}info     : {node.info['analyzer_info']}\n"
        if node.info["filename"]:
            yield f"{pad}filename : {node.info['filename']}\n"
        yield f"{pad}md5      : {node.info['md5']}\n"

        yield from self._render_reports(node.reports, prefix=pad)

        num = len(node.children)
        for i, child in enumerate(node.children):
            yield from self._render_child(child, prefix=pad, is_last=(i == num - 1))

    # ------------------------------------------------------------------
    # Reports (shared between root and children)
    # ------------------------------------------------------------------

    @staticmethod
    def _render_reports(reports: list[dict], prefix: str):
        for report in reports:
            label = report["label"]
            if report["content_type"] == "image/png":
                yield f"{prefix}{label} : [Image: {report['text'] or 'preview in HTML report'}]\n"
            else:
                text = str(report["text"]) if report["text"] is not None else ""
                lines = textwrap.wrap(text, width=100, subsequent_indent="  ")
                if not lines:
                    yield f"{prefix}{label} : \n"
                else:
                    yield f"{prefix}{label} : {lines[0]}\n"
                    for line in lines[1:]:
                        yield f"{prefix}  {line}\n"
