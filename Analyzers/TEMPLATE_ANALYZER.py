"""Template analyzer — copy this file as a starting point for new analyzers.

This file is intentionally NOT registered in ``Analyzers/__init__.py``;
it never runs. It exists as documentation-by-example for contributors.

Steps to add a new analyzer:
  1. Copy this file: ``cp TEMPLATE_ANALYZER.py MyNewAnalyzer.py``
  2. Rename the class: ``TemplateAnalyzer`` → ``MyNewAnalyzer``
  3. Set ``compatible_mime_types``, ``specificity``, dependencies
  4. Implement ``analysis()`` and any helpers it needs
  5. Add ``"MyNewAnalyzer"`` to the ``analyzers_list`` in
     ``Analyzers/__init__.py``

Audit follow-up #45: the previous version imported from a nonexistent
``.base`` module and listed placeholder pip deps (``new_dependency``,
``new_command``) that confused contributors copying the template.
This rewrite imports from the real ``structure`` module and shows the
actual extension points correctly.
"""

import logging

from structure import Analyzer, Report, Severity, AnalysisModuleException  # noqa: F401

log = logging.getLogger("matt")


# Optional dependency — wrap imports for any package the analyzer
# needs but that should be installable as an extra rather than a hard
# requirement. Replace ``some_optional_dep`` with the real import.
try:
    import some_optional_dep  # type: ignore[import-not-found]  # noqa: F401
except ImportError:
    some_optional_dep = None


class TemplateAnalyzer(Analyzer):
    """Replace this docstring with what the analyzer actually does."""

    # MIME types this analyzer claims as primary. ``can_analyze`` checks
    # this list first; supplement with ``can_handle()`` for content-based
    # probing on ambiguous types like ``application/octet-stream``.
    compatible_mime_types = ["application/x-my-new-format"]

    # Human-readable label shown by ``matt --check``.
    description = "My New Analyzer"

    # Dispatch ranking. See the project README for the convention:
    #   5  generic (PlainText)
    #   10 container (Zip, 7z, OLE)
    #   15 semi-structured (HTML)
    #   20 format (Email, PDF, Docx, Mbox, Msg)
    #   25 sub-analyzer
    specificity = 20

    # Hard pip requirements — analyzer is unavailable without these.
    # Format: list of (import_name, pip_package) tuples.
    pip_dependencies: list[tuple[str, str]] = []

    # Optional pip requirements — analyzer degrades gracefully without
    # these but ``matt --check`` will list them as install hints.
    optional_pip_dependencies = [("some_optional_dep", "some-optional-dep")]

    # Optional system binaries — discovered via ``shutil.which``.
    optional_system_dependencies: list[str] = []

    # Name of the pip extra that pulls in this analyzer's optional deps.
    # ``matt --check`` shows ``Install: pip install .[<extra>]``.
    extra = "myextra"

    @classmethod
    def can_handle(cls, struct) -> bool:
        """Optional content-based probe for ambiguous MIME types.
        Return True if this analyzer wants to run on the given Structure.
        Default: False (i.e. only run on the compatible_mime_types list).
        """
        return False

    def analysis(self) -> None:
        """Populate ``self.reports`` with findings and ``self.childitems``
        with nested ``Structure`` objects (e.g. archive entries, MIME
        parts). You can either register modules via
        ``self.modules['name'] = fn`` and call ``super().analysis()``,
        or do everything inline here."""
        if some_optional_dep is None:
            log.debug("TemplateAnalyzer: optional dep unavailable, skipping")
            return

        self.info = "Short summary shown in the analyzer-info column."

        # Example: emit a finding
        self.reports["template_finding"] = Report(
            "TemplateAnalyzer ran",
            label="template_finding",
            severity=Severity.INFO,
        )

        # Example: emit a child Structure for some extracted bytes
        # self.childitems.append(
        #     self.generate_struct(
        #         data=extracted_bytes,
        #         filename="extracted.bin",
        #         mime_type="application/octet-stream",
        #     )
        # )
