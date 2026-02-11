#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import structure
import logging
import mimetypes
from Config.config import flags
from structure import Analyzer
from Analyzers import *
import sys
import importlib.util
from Utils import filetype
from Utils.logger import setup_logging

CORE_DEPENDENCIES = [
    ("chardet", "chardet"),
    ("dateutil", "python-dateutil"),
    ("pytz", "pytz"),
]


def _dependency_missing(import_name):
    return importlib.util.find_spec(import_name) is None


def check_dependencies():
    print("Checking core dependencies...")
    core_missing = [package for module, package in CORE_DEPENDENCIES if _dependency_missing(module)]
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
        print("    note: the tool will fall back to mimetypes if no provider is available.")

    if core_missing or all_missing_required:
        print("\n[!] Some required dependencies are missing. Please install them to use all features.")
    elif all_missing_optional:
        print("\n[i] Some optional dependencies are missing. Install extras to enable additional features.")
        print("    Install all optional features: pip install .[all]")
    else:
        print("\n[OK] All dependencies are installed.")
    sys.exit(0)

def main():
    path = os.path.join(os.getcwd(),'extract')
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='*', help="Mailfiles to analyse")
    parser.add_argument("--check", help="Check if all dependencies for the analyzers are installed", action="store_true")
    parser.add_argument("-x", "--extract", help="Save all parts of the mail to files", action="store_true")
    parser.add_argument("-f", "--filenames", help="Restore original Filenames", action="store_true")
    parser.add_argument("-d", "--debug", help="Enable Debug output", action="store_true")
    parser.add_argument("-o", "--out-dir", help=f"output dir. [default={path}]", default=path)
    parser.add_argument("--format", help="Output format (text, markdown, html, json)", default="text")
    parser.add_argument("--verbosity", help="Verbosity level (0-5)", type=int, default=0)

    args = parser.parse_args()

    # Configure logging
    setup_logging(verbosity=args.verbosity, debug=args.debug)

    if args.check:
        check_dependencies()

    flags.debug=args.debug

    if not args.files:
        parser.print_help()
        sys.exit(1)

    for f in args.files:
        fpath=os.path.join(path,f)
        if not os.path.isfile(f):
            logging.warning(f"skipping {f} : not a file")
            continue

        s = structure.Structure.create(filename=f,mime_type=mimetypes.guess_type(f,strict=False)[0])
        print(s.get_report(report_format=args.format, verbosity=args.verbosity))
        if args.extract:
            s.extract(basepath=args.out_dir,filenames=args.filenames,recursive=True)

if __name__ == "__main__":
    main()
