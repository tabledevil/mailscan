#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import email
import os
import hashlib
import re

base_path="/data/cases/006_exchange/pst/"
base_path=sys.argv[1]
i=0
for root, dirs, files in os.walk(base_path):
    # path = root.split(os.sep)
    # print((len(path) - 1) * '---', os.path.basename(root))
    for file in files:
        mailfile=root+os.sep+file
        try:
            msg=email.message_from_file(open(mailfile, 'r', encoding='latin-1'))
        except Exception as e:
            print("Error %s"%mailfile)
            print(e)
            continue
        if "From" in msg.keys(): msg_from=msg.get("From")
        if "To" in msg.keys():
            msg_to=re.findall("(?<=<)[^>]+",msg.get("To"))
            msg_to=msg_to if len(msg_to) > 0 else [msg.get("To")]
        if "CC" in msg.keys():
            msg_cc=(re.findall("(?<=<)[^>]+",msg.get("CC")))
            if len(msg_cc) > 0:
                msg_to.extend(msg_cc)
            else:
                msg_to.append(msg.get("CC"))

        if "Subject" in msg.keys(): msg_subject=msg.get("Subject")
        if "Date" in msg.keys(): msg_date=msg.get("Date")
        for recp in msg_to:
            print("%s: %s > %s [%s] @ %s"%(file,msg_from,recp,msg_subject,msg_date))
        for part in msg.walk():
            if part.get_filename() is not None:
                try:
                    attachment_data=part.get_payload(decode=True)
                    md5=hashlib.md5()
                    md5.update(attachment_data)
                    filename="export/"+str(md5.hexdigest()+"-"+str(i)+"-"+file)
                    i+=1
                    # print(filename)
                    open(filename,'wb').write(attachment_data)
                except:
                    pass

# traverse root directory, and list directories as dirs and files as files
# for key in msg.keys():
#     print(key)
# for part in msg.walk():
#     mime=part.get_content_type().replace('/',"_")
#     filename=part.get_filename() if part.get_filename() is not None else "NONE"
#     print("#####################################################################")
#     print("#####################################################################")
#     print("#####################################################################")
#
#     print("mime     : " + mime)
#     print("filename : " + filename)
#     print(part)
    #     filename="None"
    # open(mime,'a').write(filename+"\n")
