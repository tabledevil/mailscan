"""Analyzer package — discovers and loads all Analyzer subclasses."""

import importlib
import logging
import sys

log = logging.getLogger("matt")

analyzers_list = [
    "EmailAnalyzer",
    "PlainTextAnalyzer",
    "ZipAnalyzer",
    "SevenZipAnalyzer",
    "HTMLAnalyzer",
    "PDFAnalyzer",
    "MsgAnalyzer",
    "MboxAnalyzer",
    "OfficeDocumentAnalyzer",
    "OLEOfficeAnalyzer",
    "OfficeRelationshipAnalyzer",
    "OfficeXMLAnalyzer",
    "VBAProjectAnalyzer",
    "RTFAnalyzer",
    "ImageAnalyzer",
    "ICSAnalyzer",
    "RARAnalyzer",
    "ScriptAnalyzer",
]

# We need the Analyzer base class to filter subclasses properly.
# It is imported lazily inside the loop to avoid circular import issues
# (structure.py imports from Analyzers, and Analyzers import from structure).
_Analyzer = None

_loaded_analyzers = []

for _module_name in analyzers_list:
    try:
        _module = importlib.import_module(f"Analyzers.{_module_name}")

        # Lazy-import the base class once
        if _Analyzer is None:
            from structure import Analyzer as _Analyzer

        # Only export actual Analyzer subclasses — not random imports like
        # 'os', 'logging', 're' etc. that polluted the namespace before.
        for _name in dir(_module):
            if _name.startswith("_"):
                continue
            _obj = getattr(_module, _name)
            if (
                isinstance(_obj, type)
                and issubclass(_obj, _Analyzer)
                and _obj is not _Analyzer
            ):
                globals()[_name] = _obj
                _loaded_analyzers.append(_name)

    except ImportError as e:
        # At import time the logging system may not be configured yet,
        # so write directly to stderr as a safety net.
        msg = f"Failed to import Analyzer {_module_name}: {e}"
        if logging.getLogger().handlers:
            log.warning(msg)
        else:
            print(f"[matt] WARNING: {msg}", file=sys.stderr)
    except Exception as e:
        msg = f"Unexpected error importing Analyzer {_module_name}: {e}"
        if logging.getLogger().handlers:
            log.warning(msg)
        else:
            print(f"[matt] WARNING: {msg}", file=sys.stderr)

__all__ = list(_loaded_analyzers)
