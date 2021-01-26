#!/usr/bin/python3
# -*- coding: utf-8 -*-
import email
import sys
import chardet
import argparse

parser = argparse.ArgumentParser()
parser.add_argument('-f', dest='field', nargs='?', action='append', help='Header field to look for')
parser.add_argument('infile', nargs='+', type=argparse.FileType('rb'))
args = parser.parse_args()

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


for file in args.infile:
    print(file.name)
    msg=email.message_from_binary_file(file)
    file.close()

    for (k,v) in msg.items():
        if args.field is not None and k.lower() not in (field.lower() for field in args.field):
            continue
        for (string,encoding) in email.header.decode_header(v):
            if encoding != None:
                value=string.decode(encoding)
            else:
                value=fdecode(string)
            value=' '.join(value.split())
            print("{}: {}".format(k,value.strip()))
