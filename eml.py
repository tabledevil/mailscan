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
from email.header import decode_header
import hashlib
from functools import lru_cache
import re
from pytz import timezone
from dateutil.parser import parse

#followin import and decorate can be removed after rework
import inspect
def depricated(fn):
    def wraper(*args,**kwargs):
        print(f'''>{inspect.stack()[1].function} called depricated function {fn.__name__}''')
        return fn(*args,**kwargs)

    return wraper

class Eml(object):
    rfc5322_mail_regex = r'''(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])'''

    mail_re = re.compile(rfc5322_mail_regex, re.IGNORECASE)
    received_p_from_details = r'''\((?P<fqdn>[^\[\] ]+)?\s?(\[(?P<ip>\S+)\])?\s*(\([^\)]+\))?\)\s*(\([^\)]+\))?\s*'''
    received_p_from = r'''from (?P<from>\S+)\s*'''+received_p_from_details
    received_p_by = r'''\s*by\s+(?P<by>\S+)\s*(\([^\)]+\))?'''
    received_p_with = r'''\s*(with\s+(?P<with>.*))?'''
    received_p_id = r'''\s*(id\s+(?P<id>\S+))\s*(\([^\)]+\))?'''
    received_p_for = r'''\s*(for\s+(?P<for>\S*))?'''
    received_p_date = r''';\s*(?P<date>\w+,\s\d+\s\w+\s\d+\s[\d:]+\s[\d+-]+\s\(\w+\)).*\s*(\([^\)]+\))?'''
    received_pattern = received_p_from+received_p_by + \
        received_p_with+received_p_id+received_p_for+received_p_date
    received_re = re.compile(received_pattern, re.IGNORECASE)

    def get_header(self, field):
        '''Get a decoded list of all values for given header field.'''
        return [self.__decode(value) for value in self.get_header_raw(field)]

    def get_header_raw(self, field):
        '''Get list of all raw values for given header field.'''
        # msg=self.get_eml()
        items = []
        for key,value in self.header:
            if key.lower() == field.lower():
                items.append(value)
        return items

    @lru_cache(maxsize=1)
    def get_eml(self):
        '''Get email.email Object for this email.'''
        return email.message_from_binary_file(open(self.filename, 'rb'))

    def get_struct(self):
        '''Get structure of email as dictionary.'''
        pass

    def get_mail_path(self):
        '''Get mail delivery path as reconstructed from received fields as list.'''
        pass

    def get_timeline(self):
        '''Get all timebased events for the mail as a list.'''
        pass

    def get_date(self,tz='UTC'):
        '''Get date of mail converted to timezone. Default is UTC.'''
        if tz is None:
            return self.date
        else:
            return self.__convert_date_tz(self.date,tz)

    def get_from(self):
        '''Get all sender indicating fields of mail as dictionary'''
        #from
        #reply-to
        #return-path
        #received envelope info
        pass

    def get_to(self):
        '''Get all recipient indicating fields of mail as a dictionary'''

        pass

    def get_subject(self):
        '''Get subject line of mail'''
        pass

    def get_index(self):
        '''Get tokenized index of all parseable text. A bit like linux strings.'''
        pass

    def get_hash(self,part='all',type='md5'):
        '''
        Get hash for selected parts.

        part = (all,body,attachments,index) index from get_struct
        type = (md5,sha256)
        '''
        hashes=[]
        if part == "all" or part == "attachments":
            hashes.extend([x[type] for x in self.attachments])

        return hashes

    def get_attachments(self,filename=None):
        '''Get list of attachments as list of dictionaries. (filename,mimetype,md5,sha256,rawdata)'''
        pass

    def get_lang(self):
        '''Get a guess about content language.'''
        pass

    def get_iocs(self,type='all'):
        '''Get dictionary of iocs'''
        pass

    def as_csv(self,selected_fields=None,delimiter=';'):
        '''
        Get a CSV-String representation of the mail.

        future : selected_fields is a list of strings
        '''
        if "done" in self.status:
            output = ""
            #date, from, to&cc, subject, msgid, filename, mimetype, hash
            to_cc = " ".join(self.tos.split()
                             + self.ccs.split()).replace(";", ",")

            msg_output = "%s;%s;%s;%s;%s;%s;" % (str(self.date).replace(";", ","), self.froms.replace(
                ";", ","), to_cc, self.subject.replace(";", ","), self.id.replace(";", ","), self.filename.replace(";", ","))

            if len(self.attachments) > 0:
                for att in self.attachments:
                    output += msg_output+att["filename"] + \
                        ";"+att["mimetype"]+";"+att["md5"]+"\n"
            else:
                output += msg_output+";;"
        else:
            output = ""
        return output.strip()

    def as_tsv(self,selected_fields):
        '''
        Return a CSV-String representation of the mail.

        future : selected_fields is a list of strings
        '''
        return self.as_csv(selected_fields,delimiter='\t')

    def as_string(self,formatstring):
        '''Return string representation of mail based on formatstring.'''
        pass

    def has_attachments(self):
        '''Return True if mail has Files Attached.'''
        return len(self.attachments)>0

    def contains_hash(self,string):
        '''Return True if the hash of any part of the Mail equals supplied string'''
        if len(string) == 64:
            return string.lower() in self.get_hash(type='sha256')
        if len(string) == 32:
            return string.lower() in self.get_hash()
        return False

    def contains_string(self,string:str) -> bool:
        '''Return True if mail contains string in its text.'''
        return string.lower() in self.get_index()

    def check_spoof(self) -> bool:
        '''Perform spoof Check on mail an return result'''
        return False

    def check_sig(self) -> bool:
        '''Perform valide smime if available and return result'''
        return False

    def check_dkim(self) -> bool:
        '''Perform check on dkim signature if available return result'''
        return False

    def check_header(self) -> bool:
        '''Perform consistancy check on header fields result'''
        return False

    def __get_mailaddresses_from_field(self, msgfield="From"):
        text = self.get_field_from(msg, "From")
        match = self.mail_re.findall(text)
        return match

    def __decode(self,string):
        '''Decode string as far as possible'''
        if isinstance(string, str):
            text,encoding = decode_header(string)[0]
            if encoding is None : return text
            else : return text.decode(encoding)
        if isinstance(string,bytes):
            for encoding in ['utf-8-sig', 'utf-16', 'cp1252']:
                try:
                    return string.decode(encoding)
                except UnicodeDecodeError:
                    pass

    @depricated
    def __strip_it(self, string):
        if isinstance(string, bytes):
            return self.__strip_it(string.decode("utf-8"))
        else:
            return " ".join(string.split()).strip()

    @depricated
    def __decode_strip_string(self, msgfield):
        if msgfield[1] is not None:
            return self.__strip_it(msgfield[0].decode(msgfield[1]))
        else:
            return self.__strip_it(msgfield[0])

    @depricated
    def __get_filetype(self, filename):
        output = os.subprocess.run(
            ["file", filename], stdout=os.subprocess.PIPE).stdout.decode('utf-8')
        return output.split(":")[1].rstrip()

    @depricated
    def __get_field_from(self, msg, field):
        if field in msg.keys():
            items = []
            for item in email.header.decode_header(msg.get(field)):
                decoded_item = self.__decode_strip_string(item)
                items.append(decoded_item)
            return " ".join(items)
        else:
            return ""

    def __convert_date_tz(self, datetime, tz='UTC'):
        return datetime.astimezone(tz=timezone(tz))

    def __str__(self):

        output = self.filename+":\n"
        if "done" in self.status:
            output += "From: %s\n" % self.froms
            output += "To: %s\n" % self.tos
            output += "Date: %s\n" % self.date
            output += "Subject: %s\n" % self.subject
        return output



    def __init__(self, filename, hash_attachments=True):
        self.status = "new"
        self.filename = filename
        try:
            # msg = email.message_from_file(open(filename, 'r', encoding='latin-1'))
            self.header = self.get_eml().items()
            self.status = "processing_header"
            self.froms = self.get_header("from")
            self.tos = self.get_header("To")
            self.ccs = self.get_header("CC")
            # self.subject = self.get_header("Subject")
            # self.id = self.get_header("Message-ID")
            # self.date = email.utils.parsedate_to_datetime(self.get_header("Date"))
            # self.received = self.get_header("Received")
            # self.status = "processing_attachments"
            # self.attachments = []
            # if hash_attachments:
            #     for part in self.get_eml().walk():
            #         if part.get_filename() is not None:
            #             self.status = self.status+"."
            #             attachment = {}
            #             attachment["filename"] = self.__decode(part.get_filename())
            #             attachment["mimetype"] = part.get_content_type()
            #             attachment['rawdata'] = part.get_payload(decode=True)
            #             attachment["md5"] = hashlib.md5(attachment['rawdata']).hexdigest()
            #             attachment["sha256"] = hashlib.sha256(attachment['rawdata']).hexdigest()
            #             self.attachments.append(attachment)
            self.status = "done"
        except Exception as e:
            self.status = "not_parsable" + str(e)


def create_newmail(filename):
    return Eml(filename)

def scan_folder(basepath):
    import multiprocessing as mp
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
