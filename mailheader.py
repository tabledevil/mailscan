#!/usr/bin/python3
# -*- coding: utf-8 -*-
import email
import sys

with open(sys.argv[1],'r',encoding='latin-1') as f:
    msg_data=f.read()
    msg=email.message_from_string(msg_data)

for (k,v) in msg.items():
    for (string,encoding) in email.header.decode_header(v):
        if encoding != None:
            value=string.decode(encoding)
        else:
            value=string
        print("{}: {} ({})".format(k,value,type(value)))
