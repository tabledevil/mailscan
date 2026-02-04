#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import email
import os
import hashlib
import chardet

def fdecode(string):
    if isinstance(string, str):
        text, encoding = email.header.decode_header(string)[0]
        if encoding is None:
            return text
        else:
            return text.decode(encoding)
    if isinstance(string, bytes):
        encodings = ['utf-8-sig', 'utf-16', 'iso-8859-15']
        detection = chardet.detect(string)
        if "encoding" in detection and len(detection["encoding"]) > 2:
            encodings.insert(0,detection["encoding"])
        for encoding in encodings:
            try:
                return string.decode(encoding)
            except UnicodeDecodeError:
                pass


base_path=sys.argv[1]
i=0
for root, dirs, files in os.walk(base_path):
    # path = root.split(os.sep)
    # print((len(path) - 1) * '---', os.path.basename(root))
    for file in files:
        mailfile=root+os.sep+file
        try:
            with open(mailfile, 'r', encoding='latin-1') as f:
                msg=email.message_from_file(f)
        except Exception as e:
            print("Error %s"%mailfile)
            print(e)
            continue
        if "From" in msg.keys(): msg_from=msg.get("From")
        if "Subject" in msg.keys(): msg_subject=msg.get("Subject")
        if "Date" in msg.keys(): msg_date=msg.get("Date")
        for part in msg.walk():
            if part.get_filename() is not None:
                try:
                    attachment_data=part.get_payload(decode=True)
                    md5=hashlib.md5()
                    md5.update(attachment_data)
                    filename="export/"+file+"/"+str(md5.hexdigest())+"-"+str(i)+"-"+fdecode(part.get_filename())
                    i+=1
                    print(filename)
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
