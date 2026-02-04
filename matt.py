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
    missing_optional = []
    missing_required = []
    for analyzer in Analyzer.__subclasses__():
        status = analyzer.dependency_status()
        if status["missing_required"]:
            missing_required.extend(status["missing_required"])
            print(f"  - {analyzer.description}: [MISSING REQUIRED] {', '.join(status['missing_required'])}")
        else:
            if status["missing_optional"]:
                missing_optional.extend(status["missing_optional"])
                optional_text = ", ".join(status["missing_optional"])
                print(f"  - {analyzer.description}: [OK] (optional missing: {optional_text})")
                extra = getattr(analyzer, "extra", None)
                if extra:
                    print(f"      install: pip install .[{extra}]")
            else:
                print(f"  - {analyzer.description}: [OK]")

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

    if core_missing or missing_required:
        print("\nSome required dependencies are missing. Please install them to use all features.")
    elif missing_optional:
        print("\nSome optional dependencies are missing. Install extras to enable additional features.")
        print("  - Install all optional features: pip install .[all]")
    else:
        print("\nAll dependencies are installed.")
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
