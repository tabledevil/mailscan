#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""MATT — Mail Analysis and Triage Tool.

CLI entry point.  Recursively dissects email files, archives, and
attachments into a tree of analysis reports.
"""

import argparse
import importlib.util
import logging
import mimetypes
import os
import sys

import structure
from Config.config import flags
from renderers import available_formats
from structure import Analyzer
from Analyzers import *  # noqa: F401,F403 — register all analyzers
from Utils import filetype
from Utils.logger import setup_logging

log = logging.getLogger("matt")

# ------------------------------------------------------------------
# Core dependencies (import_name, pip_package)
# ------------------------------------------------------------------
CORE_DEPENDENCIES = [
    ("charset_normalizer", "charset-normalizer"),
    ("dateutil", "python-dateutil"),
    ("pytz", "pytz"),
    ("rich", "rich"),
]


def _dependency_missing(import_name):
    return importlib.util.find_spec(import_name) is None


# ------------------------------------------------------------------
# --check
# ------------------------------------------------------------------
def check_dependencies():
    print("Checking core dependencies...")
    core_missing = [
        package for module, package in CORE_DEPENDENCIES if _dependency_missing(module)
    ]
    if core_missing:
        print(f"  - Missing required packages: {', '.join(core_missing)}")
    else:
        print("  - Core dependencies: [OK]")

    print("\nChecking analyzer dependencies...")

    all_missing_required = []
    all_missing_optional = []

    analyzers = set(Analyzer.__subclasses__())
    analyzers = [a for a in analyzers if a is not Analyzer]

    for analyzer in sorted(analyzers, key=lambda x: x.description or x.__name__):
        status = analyzer.dependency_status()

        missing_req = status.get("missing_required", [])
        missing_opt = status.get("missing_optional", [])
        missing_alt = status.get("missing_alternatives", [])

        all_missing_required.extend(missing_req)
        all_missing_required.extend(missing_alt)
        all_missing_optional.extend(missing_opt)

        msgs = []
        if missing_req:
            msgs.append(f"[ERROR] Missing required: {', '.join(missing_req)}")

        if missing_alt:
            for alt in missing_alt:
                msgs.append(f"[ERROR] Missing alternative: {alt}")

        if missing_opt:
            msgs.append(f"[WARNING] Missing optional: {', '.join(missing_opt)}")

        if not msgs:
            print(f"  - {analyzer.description}: [OK]")
        else:
            print(f"  - {analyzer.description}:")
            for msg in msgs:
                print(f"      {msg}")

            extra = getattr(analyzer, "extra", None)
            if extra:
                print(f"      Install: pip install .[{extra}]")

    print("\nChecking MIME detection providers...")
    provider_order = filetype.get_provider_order()
    print(f"  - Provider order: {', '.join(provider_order)}")
    provider_status = filetype.get_provider_status(provider_order)
    for entry in provider_status:
        if entry["available"]:
            print(f"  - {entry['provider']}: [OK]")
        else:
            print(f"  - {entry['provider']}: [MISSING] {entry['reason']}")

    if any(not entry["available"] for entry in provider_status):
        print("    install: pip install .[mime]")
        print(
            "    note: the tool will fall back to mimetypes if no provider is available."
        )

    print(f"\nAvailable output formats: {', '.join(available_formats())}")

    if core_missing or all_missing_required:
        print(
            "\n[!] Some required dependencies are missing. Please install them to use all features."
        )
    elif all_missing_optional:
        print(
            "\n[i] Some optional dependencies are missing. Install extras to enable additional features."
        )
        print("    Install all optional features: pip install .[all]")
    else:
        print("\n[OK] All dependencies are installed.")
    sys.exit(0)


# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------
def main():
    # A6: Force UTF-8 on stdout/stderr to avoid encoding errors on Windows
    if sys.stdout and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if sys.stderr and hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    default_out = os.path.join(os.getcwd(), "extract")
    formats = ", ".join(available_formats())

    parser = argparse.ArgumentParser(
        prog="matt",
        description="MATT — Mail Analysis and Triage Tool",
    )
    parser.add_argument("files", nargs="*", help="Files to analyse")
    parser.add_argument(
        "--check",
        help="Check if all dependencies for the analyzers are installed",
        action="store_true",
    )
    parser.add_argument(
        "-x",
        "--extract",
        help="Save all parts of the mail to files",
        action="store_true",
    )
    parser.add_argument(
        "-f",
        "--filenames",
        help="Restore original filenames",
        action="store_true",
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Enable debug output",
        action="store_true",
    )
    parser.add_argument(
        "-o",
        "--out-dir",
        help=f"Output directory [default: {default_out}]",
        default=default_out,
    )
    parser.add_argument(
        "--format",
        help=f"Output format ({formats}) [default: rich]",
        default=flags.default_format,
    )
    parser.add_argument(
        "-v",
        "--verbosity",
        help="Verbosity level 0-5 [default: 0]",
        type=int,
        default=flags.default_verbosity,
    )
    parser.add_argument(
        "--network-policy",
        help="Network policy: offline, passive, online [default: passive]",
        choices=["offline", "passive", "online"],
        default=flags.network_policy,
    )

    args = parser.parse_args()

    # Apply flags from CLI
    flags.debug = args.debug
    flags.network_policy = args.network_policy

    # Configure logging
    setup_logging(verbosity=args.verbosity, debug=args.debug)

    if args.check:
        check_dependencies()

    if not args.files:
        parser.print_help()
        sys.exit(1)

    for filepath in args.files:
        if not os.path.isfile(filepath):
            log.warning(f"Skipping {filepath}: not a file")
            continue

        mime = mimetypes.guess_type(filepath, strict=False)[0]
        s = structure.Structure.create(filename=filepath, mime_type=mime)
        print(s.get_report(report_format=args.format, verbosity=args.verbosity))

        if args.extract:
            s.extract(
                basepath=args.out_dir,
                filenames=args.filenames,
                recursive=True,
            )

        # Free memory between top-level files
        structure.Structure.clear_cache()


if __name__ == "__main__":
    main()
