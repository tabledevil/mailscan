"""Timeline output renderer — chronological event listing."""

from __future__ import annotations

from renderers import Renderer, _register


@_register
class TimelineRenderer(Renderer):
    format_name = "timeline"

    def _render(self, tree, verbosity):
        if not self._timeline:
            return "No timeline events found.\n"
        lines = []
        for event in self._timeline:
            lines.append(f"{event['timestamp']}  {event['event']:<25} {event['source']}")
            if event.get("details"):
                lines.append(f"{'':>28}{event['details']}")
        return "\n".join(lines) + "\n"
