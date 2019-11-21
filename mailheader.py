#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import sys
import dkim


with open(sys.argv[1],'r',encoding='latin-1') as f:

    # msg=email.message_from_file(f)
    msg_data=f.read()
    msg=email.message_from_string(msg_data)

def strip_it(string):
    if isinstance(string,bytes):
        return strip_it(string.decode("utf-8"))
    else:
        return " ".join(string.split()).strip()

def decode_strip_string(msgfield):
    if msgfield[1] is not None:
        return strip_it(msgfield[0].decode(msgfield[1]))
    else:
        return strip_it(msgfield[0])

def get_field_from(msg,field):
    if field in msg.keys():
        items=[]
        for item in email.header.decode_header(msg.get(field)):
            decoded_item=decode_strip_string(item)
            items.append(decoded_item)
        return " ".join(items)
    else:
        return ""


for (k,v) in msg.items():
    for (string,encoding) in email.header.decode_header(v):
        if encoding != None:
            value=string.decode(encoding)
        else:
            value=string
        print("{}: {}".format(k,value))
