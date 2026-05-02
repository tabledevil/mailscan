"""JSON renderer — produces machine-readable output."""

from __future__ import annotations

import json

from renderers import Renderer, ReportNode, _register


_SEVERITY_NAME = {0: "CRITICAL", 1: "HIGH", 2: "MEDIUM", 3: "LOW", 4: "INFO"}


def _tree_max_severity(node: ReportNode) -> int:
    worst = node.max_severity
    for child in node.children:
        worst = min(worst, _tree_max_severity(child))
    return worst


@_register
class JsonRenderer(Renderer):
    format_name = "json"

    def _render(self, tree: ReportNode, verbosity: int) -> str:
        return json.dumps(self._to_dict(tree), indent=2, ensure_ascii=False)

    def _to_dict(self, node: ReportNode) -> dict:
        own_sev = node.max_severity
        tree_sev = _tree_max_severity(node)
        return {
            "info": node.info,
            "severity": {
                "own": _SEVERITY_NAME.get(own_sev, "INFO"),
                "own_value": own_sev,
                "tree_max": _SEVERITY_NAME.get(tree_sev, "INFO"),
                "tree_max_value": tree_sev,
            },
            "reports": node.reports,
            "children": [self._to_dict(c) for c in node.children],
        }
