#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import hashlib
import sys
import re
import subprocess
from eml import Eml

possible_spoofs=[]
senders=[]
nodes={}
basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
try:
    for root, dirs, files in os.walk(basepath):
        path = root.split(os.sep)
        relpath = os.sep.join(root.split(os.sep)[basecount:])
        for file in files:
            filename=root+os.sep+file
            relfilename=relpath+os.sep+file
            try:
                msg=Eml(filename,hash_attachments=False)
                match=msg.get_mailaddresses_from_field()
                if len(match) > 0:
                    senders.append([match[0],filename])
                if(len(match)) > 1:
                    first=match[0].lower()
                    if not all(mail.lower()==first for mail in match[1:]):
                        possible_spoofs.append(msg)
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as e:
                print("Error processing %s [%s]" % (filename,e))
                continue
except:
    pass
finally:


    with open('sender.txt','w') as f:
        for x in sorted(senders):
            f.write(str(x)+"\n")

    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("!!Possible Spoof mails  !!!!!!!!!")
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

    for x in possible_spoofs:
        print(x)
