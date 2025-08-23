#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import structure
import logging
import mimetypes
from Config.config import flags
from Analyzers.base import BaseAnalyzer
from Analyzers import *
import sys

def check_dependencies():
    print("Checking dependencies...")
    all_ok = True
    for analyzer in BaseAnalyzer.__subclasses__():
        available, reason = analyzer.is_available()
        if not available:
            all_ok = False
            print(f"  - {analyzer.description}: [FAILED] {reason}")
        else:
            print(f"  - {analyzer.description}: [OK]")
    if not all_ok:
        print("\nSome dependencies are missing. Please install them to use all features.")
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
        print(s.get_report())
        if args.extract:
            s.extract(basepath=args.out_dir,filenames=args.filenames,recursive=True)

if __name__ == "__main__":
    main()
            

