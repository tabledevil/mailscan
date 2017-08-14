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


if __name__ == '__main__':


    list_of_mail=[]
    basepath=sys.argv[1]
    basecount=len(basepath.split(os.sep))-1
    if os.path.isfile(basepath):
        e=Eml(basepath)
        print(e)
    else:
        with mp.Pool(processes=4) as pool:

            for root, dirs, files in os.walk(basepath):
                path = root.split(os.sep)
                relpath = os.sep.join(root.split(os.sep)[basecount:])

                new_mails=pool.map(create_newmail,[root+os.sep+s for s in files])
                list_of_mail.extend(new_mails)
                # for filename in (root+os.sep+s for s in files):
                    # print(filename)
                    # e=Eml(filename)

        pool.close()
        pool.join()



    # for mail in list_of_mail:
    #     mail.join()
    #
    for mail in list_of_mail:
        if "done" in mail.status:
            print(mail.get_csv())
        else:
            pass
