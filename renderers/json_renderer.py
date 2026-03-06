"""JSON renderer — produces machine-readable output."""

from __future__ import annotations

import json

from renderers import Renderer, ReportNode, _register


@_register
class JsonRenderer(Renderer):
    format_name = "json"

    def _render(self, tree: ReportNode, verbosity: int) -> str:
        return json.dumps(self._to_dict(tree), indent=2, ensure_ascii=False)

    def _to_dict(self, node: ReportNode) -> dict:
        return {
            "info": node.info,
            "reports": node.reports,
            "children": [self._to_dict(c) for c in node.children],
        }
