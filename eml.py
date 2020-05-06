#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Eml - Wrapper class for email-objects

This Class is supposed to add needed decoding and formating to the email objects.
Furthermore file attachments get hashed.

In the Future these objects are supposed to be items in searchable catalogue.



@author tke
"""
import os
import email
import hashlib
import sys
import re
from pytz import timezone
import pickle


class Eml(object):
    rfc5322_mail_regex=r'''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''
    mail_re=re.compile(rfc5322_mail_regex,re.IGNORECASE)

    def get_mailaddresses_from_field(self,msgfield="From"):
        text=self.froms
        match=self.mail_re.findall(text)
        return match


    def strip_it(self,string):
        if isinstance(string,bytes):
            return self.strip_it(string.decode("utf-8"))
        else:
            return " ".join(string.split()).strip()

    def decode_strip_string(self,msgfield):
        if msgfield[1] is not None:
            return self.strip_it(msgfield[0].decode(msgfield[1]))
        else:
            return self.strip_it(msgfield[0])


    def get_filetype(self,filename):
        output=subprocess.run(["file",filename],stdout=subprocess.PIPE).stdout.decode('utf-8')
        return output.split(":")[1].rstrip()


    def get_field_from(self,msg,field):
        if field in msg.keys():
            items=[]
            for item in email.header.decode_header(msg.get(field)):
                decoded_item=self.decode_strip_string(item)
                items.append(decoded_item)
            return " ".join(items)
        else:
            return ""


    def convert_date_utc(self,datetime):
        return datetime.astimezone(tz=timezone('UTC'))

    def get_date_utc(self):
        return self.convert_date_utc(self.date)

    def __str__(self):
        output=self.filename+":\n"
        if "done" in self.status:
            output+="From: %s\n" % self.froms
            output+="To: %s\n" % self.tos
            output+="Date: %s\n" % self.date
            output+="Subject: %s\n" % self.subject
        return output

    def get_csv(self):
        if "done" in self.status:
            output=""
            #date,from,to&cc,subject,msgid,filename,mimetype,hash
            to_cc=" ".join(self.tos.split() + self.ccs.split()).replace(";",",")

            msg_output="%s;%s;%s;%s;%s;%s;"%(str(self.date).replace(";",","),self.froms.replace(";",","),to_cc,self.subject.replace(";",","),self.id.replace(";",","),self.filename.replace(";",","))

            if len(self.attachments)>0:
                for att in self.attachments:
                    output+=msg_output+att["filename"]+";"+att["mimetype"]+";"+att["md5"]+"\n"
            else:
                output+=msg_output+";;"
        else:
            output=""
        return output.strip()


    def __init__(self,filename,hash_attachments=True):
        self.status="new"
        self.filename=filename
        try:
            msg=email.message_from_file(open(filename,'r',encoding='latin-1'))
            self.header=msg.items()
            self.status="processing_header"
            self.froms=self.get_field_from(msg,"From")
            self.tos=self.get_field_from(msg,"To")
            self.ccs=self.get_field_from(msg,"CC")+" "+self.get_field_from(msg,"Cc")
            self.subject=self.get_field_from(msg,"Subject")
            self.id=self.get_field_from(msg,"Message-ID")
            self.date=email.utils.parsedate_to_datetime(self.get_field_from(msg,"Date"))
            self.status="processing_attachments"
            self.attachments=[]
            if hash_attachments :
                for part in msg.walk():
                    if part.get_filename() is not None:
                        self.status=self.status+"."
                        attachment={}
                        attachment["filename"]=part.get_filename()
                        attachment["mimetype"]=part.get_content_type()
                        attachment["md5"]=hashlib.md5(part.get_payload(decode=True)).hexdigest()
                        self.attachments.append(attachment)
            self.status="done"
        except Exception as e:
            self.status="not_parsable" + str(e)
            print(e)



import multiprocessing as mp

def create_newmail(filename):
    return Eml(filename)

def scan(basepath):
    list_of_mail=[]
    basecount=len(basepath.split(os.sep))-1
    if os.path.isfile(basepath):
        e=Eml(basepath)
        print(e)
    else:
        with mp.Pool(processes=mp.cpu_count()) as pool:

            for root, dirs, files in os.walk(basepath):
                path = root.split(os.sep)
                relpath = os.sep.join(root.split(os.sep)[basecount:])

                new_mails=pool.map(create_newmail,[root+os.sep+s for s in files])
                list_of_mail.extend(new_mails)

        pool.close()
        pool.join()
    return list_of_mail

if __name__ == '__main__':
    a=scan(sys.argv[1])
