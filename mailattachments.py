#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import email
import os
import hashlib
import chardet
import argparse
import eml

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

def get_md5(data):
    md5=hashlib.md5()
    md5.update(data)
    return str(md5.hexdigest())

def print_attachments(msg_data):
    msg_md5=get_md5(msg_data)
    msg=email.message_from_bytes(msg_data)
    print("Attachments in Mail [{}]".format(msg_md5))
    j=0
    for part in msg.walk():
        label='part'+str(j)
        if part.get_filename() is not None:
            print(part.get_filename())
            try:
                att_data=part.get_payload(decode=True)
                md5=get_md5(att_data)
                filename=fdecode(part.get_filename())
                i+=1
                print("{:02d}:{} >>{}<<".format(i,md5,filename))
            except:
                pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('files', nargs='+', type=argparse.FileType('rb'))
    args = parser.parse_args()
    i=0
    for f in args.files:
        print_attachments(f.read())
        # e=eml.Eml(f.name)
        # print(e)
        # print(e.struct)
        f.close()



    

