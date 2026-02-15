#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import sys
import pickle
import multiprocessing as mp
from eml import Eml


def create_newmail(filename):
    return Eml(filename)

def get_files(basepath):
    for root, dirs, files in os.walk(basepath):
        for s in files:
            yield os.path.join(root, s)

if __name__ == '__main__':

    basepath=sys.argv[1]

    if os.path.isfile(basepath):
        e=Eml(basepath)
        print(e)
    else:
        with mp.Pool(processes=mp.cpu_count()) as pool:
            for mail in pool.imap(create_newmail, get_files(basepath)):
                if "done" in mail.status:
                    print(mail.get_csv())
