#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import structure
import logging
import mimetypes
from Config.config import flags

if __name__ == "__main__":
    path = os.path.join(os.getcwd(),'extract')
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+', help="Mailfiles to analyse")
    parser.add_argument("-x", "--extract", help="Save all parts of the mail to files", action="store_true")
    parser.add_argument("-f", "--filenames", help="Restore original Filenames", action="store_true")
    parser.add_argument("-d", "--debug", help="Enable Debug output", action="store_true")
    parser.add_argument("-o", "--out-dir", help=f"output dir. [default={path}]", default=path)
    args = parser.parse_args()
    
    flags.debug=args.debug

    for f in args.files:
        fpath=os.path.join(path,f)
        if not os.path.isfile(f):
            logging.warning(f"skipping {f} : not a file")
            continue
        s = structure.Structure(filename=f,mime_type=mimetypes.guess_type(f,strict=False)[0])
        print(s.get_report())
        if args.extract:
            s.extract(basepath=args.out_dir,filenames=args.filenames,recursive=True)
            

