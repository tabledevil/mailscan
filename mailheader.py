#!/usr/bin/python3
# -*- coding: utf-8 -*-
import email
import sys
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

with open(sys.argv[1],'r',encoding='latin-1') as f:
    msg_data=f.read()
    msg=email.message_from_string(msg_data)

for (k,v) in msg.items():
    for (string,encoding) in email.header.decode_header(v):
        if encoding != None:
            value=string.decode(encoding)
        else:
            value=fdecode(string)
        value=' '.join(value.split())
        print("{}: {}".format(k,value.strip()))
