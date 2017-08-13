#!/usr/bin/python3
# -*- coding: utf-8 -*-
import os
import email
import hashlib
import sys
import re
import subprocess

notamail=[]
froms=[]

def strip_it(string):
    if isinstance(string,bytes):
        return strip_it(string.decode("utf-8"))
    else:
        return " ".join(string.split()).strip()


def get_headercontent(msgfield):
    if msgfield[1] is not None:
        return strip_it(msgfield[0].decode(msgfield[1]))
    else:
        return strip_it(msgfield[0])


def get_filetype(filename):
    output=subprocess.run(["file",filename],stdout=subprocess.PIPE).stdout.decode('utf-8')
    return output.split(":")[1].rstrip()

emailaddresspatter_rfc5322=r'''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''
emailpattern=re.compile(emailaddresspatter_rfc5322,re.IGNORECASE)

basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
for root, dirs, files in os.walk(basepath):
    path = root.split(os.sep)
    relpath = os.sep.join(root.split(os.sep)[basecount:])
    for file in files:
        filename=root+os.sep+file
        relfilename=relpath+os.sep+file
        try:
            msg=email.message_from_file(open(filename,'r',encoding='latin-1'))
        except:
            notamail.append(filename)
            continue

## for header in msg.get header einmal decoden
        if "From" in msg.keys():
            senders=[]
            for sender in email.header.decode_header(msg.get("From")):
                decoded_sender=get_headercontent(sender)
                senders.append(decoded_sender)
            froms.append(file+ ":" + " ".join(senders))
            print(file+ ":" + " ".join(senders))
        #
        #         foundmail=emailpattern.findall(sender)
        #         if foundmail is not None:
        #             for ma in foundmail:
        #                 list_senders.add(ma)
        # if len(list_senders)>0:
        #     # print(file+":"+str(list_senders))
        #     pass
        # else:
        #     print(relfilename)
        #     # print(filetype)

not_parsable=open('not_parsable.list','w')
for item in notamail:
    filetype=get_filetype(item)
    not_parsable.write("%s:%s\n" % (filetype,item))

froms_out=open('froms.list','w')
for item in froms:
    froms_out.write("%s\n"%item)
