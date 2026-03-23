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
            if report["content_type"] == "application/x-matt-hops":
                yield from TextRenderer._render_hop_list(report, prefix)
            elif report["content_type"] == "image/png":
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

    @staticmethod
    def _render_hop_list(report: dict, prefix: str):
        """Render mail route as individual hop blocks."""
        hops = report.get("data", {}).get("hops", [])
        if not hops:
            # Fall back to plain text
            text = str(report["text"]) if report["text"] else ""
            yield f"{prefix}mail_route : {text}\n"
            return

        yield f"{prefix}mail_route :\n"
        pad = prefix + "  "

        for hop in hops:
            num = hop["hop"]
            by = hop["by_hostname"]
            by_ip = hop.get("by_ip", "")
            ts = hop.get("timestamp", "")
            delta = hop.get("delta_display", "")

            # Line 1: HOP N  server [IP]  timestamp  (+delta)
            by_str = by
            if by_ip and by_ip != by:
                by_str += f" [{by_ip}]"

            line1 = f"{pad}HOP {num:<2} {by_str}"
            # Right-align timestamp
            if ts:
                line1 = f"{line1:<55} {ts}"
            if delta:
                line1 += f"  (+{delta})" if hop.get("delta_seconds", 0) is not None and hop.get("delta_seconds", 0) >= 0 else f"  ({delta})"
            yield f"{line1}\n"

            # Line 2: from
            from_name = hop.get("from_name", "?")
            from_ip = hop.get("from_ip", "")
            from_str = from_name
            if from_ip and from_ip != from_name:
                from_str += f" [{from_ip}]"
            ann = hop.get("annotations", [])
            if ann:
                from_str += f" ({', '.join(ann)})"
            yield f"{pad}       from    : {from_str}\n"

            # Line 3: proto, tls, server
            details = []
            if hop.get("protocol"):
                details.append(f"proto: {hop['protocol']}")
            tls = hop.get("tls") or hop.get("cipher")
            if tls:
                details.append(f"tls: {tls}")
            elif hop.get("no_tls"):
                details.append("tls: NONE")
            if hop.get("server_type"):
                details.append(f"server: {hop['server_type']}")
            if hop.get("authenticated_sender"):
                details.append(f"auth: {hop['authenticated_sender']}")
            if details:
                yield f"{pad}       {'   '.join(details)}\n"

            # Line 4: tz-shift (only if changed)
            if hop.get("tz_changed"):
                yield f"{pad}       tz-shift: {hop['prev_tz']} \u2192 {hop['tz_offset']}\n"

            # Inferred hops after this one
            for inf in hop.get("inferred_after", []):
                yield f"{pad}  ~    [inferred] {inf.get('label', '')}\n"

            yield f"{pad}\n"

        # Footer items (MUA, X-Originating-IP, etc.)
        if hops:
            last_hop = hops[-1]
            for item in last_hop.get("footer", []):
                yield f"{pad}{item.get('label', '')}\n"
