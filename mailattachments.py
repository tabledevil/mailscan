#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import sys
import eml
import queue
import pprint

if __name__ == "__main__":
    path = os.path.join(os.getcwd(),'extract')
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+', help="Mailfiles to analyse")
    parser.add_argument("-x", "--extract", help="Save all parts of the mail to files", action="store_true")
    parser.add_argument("-o", "--out-dir", help="output dir. [default={}]".format(path), default=path)
    args = parser.parse_args()
    
    for f in args.files:
        e = eml.Eml(f)
        print(e)
        if args.extract:
            fpath=os.path.join(args.out_dir,e.md5)
            if not os.path.isdir(fpath):
                print("Creating folder {}".format(fpath))
                os.makedirs(fpath)

            q = queue.Queue()
            q.put(e.struct)

            while not q.empty():
                x = q.get()
                if 'data' in x:
                    if 'filename' in x:
                        pfpath=os.path.join(fpath,x['filename'])
                    else:
                        filename = '.'.join([x['md5'],x['mime'].replace("/","_")])
                        pfpath = os.path.join(fpath,filename)
                    
                    print(pfpath)
                    with open(pfpath,'wb') as of:
                        of.write(x['data'])

                if 'parts' in x:
                    for p in x['parts']:
                        q.put(p)




    

