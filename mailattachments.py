#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import eml


if __name__ == "__main__":
    path = os.path.join(os.getcwd(),'extract')
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+', help="Mailfiles to analyse")
    parser.add_argument("-x", "--extract", help="Save all parts of the mail to files", action="store_true")
    parser.add_argument("-f", "--filenames", help="Restore original Filenames", action="store_true")
    parser.add_argument("-o", "--out-dir", help="output dir. [default={}]".format(path), default=path)
    args = parser.parse_args()
    
    for f in args.files:
        if os.path.isfile(f):
            e = eml.Eml(f)
            print(e)
            if args.extract:
                fpath=os.path.join(args.out_dir,e.md5)
                if not os.path.isdir(fpath):
                    print("Creating folder {}".format(fpath))
                    os.makedirs(fpath)
                for x in e.flat_struct:
                    if 'data' in x:
                        if args.filenames and 'filename' in x:
                            pfpath=os.path.join(fpath,x['filename'])
                        else:
                            filename = '.'.join([x['md5'],x['mime'].replace("/","_")])
                            pfpath = os.path.join(fpath,filename)
                        print(x['index'],pfpath)
                        with open(pfpath,'wb') as of:
                            of.write(x['data'])
                    else:
                        print(x['index'],x['content_type'])