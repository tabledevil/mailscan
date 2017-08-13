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

class Eml():
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


    def get_filetype(filename):
        output=subprocess.run(["file",filename],stdout=subprocess.PIPE).stdout.decode('utf-8')
        return output.split(":")[1].rstrip()


    def get_field_from(msg,field):
        if field in msg.keys():
            items=[]
            for item in email.header.decode_header(msg.get(field)):
                decoded_item=decode_strip_string(item)
                items.append(decoded_item)
            return " ".join(items)
        else:
            return ""

    def get_from_from(msg):
        return get_field_from(msg,"From")

    def process(filename):
        global notamail
        global froms
        try:
            msg=email.message_from_file(open(filename,'r',encoding='latin-1'))
            senders=get_field_from(msg,"Cc")
            froms.append(file+ ":" + senders)
            print(file+ ":" + senders)
        except:
            notamail.append(filename)


    def __init__(self,filename):
        self.status="new"
        try:
            msg=email.message_from_file(open(filename,'r',encoding='latin-1'))
            self.status="processing"
            self.froms=get_field_from(msg,"From")
            self.tos=get_field_from(msg,"To")
            self.ccs=get_field_from(msg,"CC")+" "+get_field_from(msg,"Cc")
            self.subject=get_field_from(msg,"Subject")
            self.status="done"
        except:
            self.status="not_parsable"





emailaddresspatter_rfc5322=r'''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''
emailpattern=re.compile(emailaddresspatter_rfc5322,re.IGNORECASE)
list_fo_mail=[]
basepath=sys.argv[1]
basecount=len(basepath.split(os.sep))-1
if os.path.isfile(basepath):
    process(basepath)
else:
    for root, dirs, files in os.walk(basepath):
        path = root.split(os.sep)
        relpath = os.sep.join(root.split(os.sep)[basecount:])
        for file in files:
            filename=root+os.sep+file
            relfilename=relpath+os.sep+file
            # process(filename)
            list_fo_mail.append(Eml(filename))

for mail in list_fo_mail:
    print(mail.froms)
# not_parsable=open('not_parsable.list','w')
# for item in notamail:
#     filetype=get_filetype(item)
#     not_parsable.write("%s:%s\n" % (filetype,item))
#
# froms_out=open('froms.list','w')
# for item in froms:
#     froms_out.write("%s\n"%item)
