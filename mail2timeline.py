#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import hashlib
import sys
import re
import subprocess
from dateutil import parser
from pytz import timezone
from getallfromfields import Eml

def get_csv_string(*args):
    return ";".join([" ".join(str(argument).split()).strip().replace(";",",") for argument in args])



basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
for root, dirs, files in os.walk(basepath):
    path = root.split(os.sep)
    relpath = os.sep.join(root.split(os.sep)[basecount:])
    for file in files:
        # print("=============================================================================================")
        filename=root+os.sep+file
        relfilename=relpath+os.sep+file
        try:

            # file_handle=open(root+os.sep+file)
            msg=email.message_from_file(open(filename,encoding="latin-1"))
            for rec in msg.get_all("Received"):
                record=" ".join(rec.split())
                stringrest,stringdate=record.split(";")

                dt = parser.parse(stringdate)
                ts_utc=dt.astimezone(tz=timezone('UTC'))
                msg_id=msg.get("Message-ID")
                # print(stringdate)
                # print(dt)
                # print("%s  | %s | %s"%(str(ts_utc),msg_id,stringrest))
                print(get_csv_string(str(ts_utc),msg_id,stringrest))

            # for key in msg.items():
            #
            #     print(key)

        except Exception as e:
            # print("-"+filename)
            # print (e)
            continue
