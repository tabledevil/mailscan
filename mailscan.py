#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import hashlib
import sys
import re
import subprocess
from getallfromfields import Eml


basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
for root, dirs, files in os.walk(basepath):
    path = root.split(os.sep)
    relpath = os.sep.join(root.split(os.sep)[basecount:])
    for file in files:
        filename=root+os.sep+file
        relfilename=relpath+os.sep+file
        try:

            # file_handle=open(root+os.sep+file)
            msg=email.message_from_file(open(filename,encoding="latin-1"))
            if msg.is_multipart():
                if "From" in msg.keys():
                    msg_from=msg.get("From").replace(";",",")
                else:
                    msg_from="UNKNOWN"
                if "Date" in msg.keys():
                    msg_date=msg.get("Date").replace(";",",")
                else:
                    msg_date="UNKNOWN"

                for part in msg.walk():
                    if part.get_filename() is not None:
                        att_hash=hashlib.md5(part.get_payload(decode=True)).hexdigest()
                        att_filename=part.get_filename().replace(";",",")
                        att_mimetype=part.get_content_type().replace(";",",")
                        msg_filename=relfilename.replace(";",",")
                        print("%s;%s;%s;%s;%s;%s" % (att_filename,att_mimetype,att_hash,msg_date,msg_from,msg_filename))
                        # print("%s;%s" % (part.get_filename(),md5.hexdigest()))
            else:
                pass




        except Exception as e:
            print("-"+filename)
            print (e)
